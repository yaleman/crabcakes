use std::io::BufReader;
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

use crate::cli::Cli;
use crate::credentials::CredentialStore;
use crate::error::CrabCakesError;
use crate::filesystem::FilesystemService;
use crate::policy::PolicyStore;
use crate::s3_handlers::S3Handler;

pub struct Server {
    host: String,
    port: NonZeroU16,
    root_dir: PathBuf,
    config_dir: PathBuf,
    require_signature: bool,
    region: String,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
}

impl Server {
    pub fn new(cli: Cli) -> Self {
        Self {
            host: cli.host,
            port: cli.port,
            root_dir: cli.root_dir,
            config_dir: cli.config_dir,
            require_signature: cli.require_signature,
            region: cli.region,
            tls_cert: cli.tls_cert,
            tls_key: cli.tls_key,
        }
    }

    /// Create a server instance for testing that binds to a random available port
    pub async fn test_mode(root_dir: PathBuf) -> Result<(Self, u16), CrabCakesError> {
        // Try to find an available port in the high port range
        let host = "127.0.0.1".to_string();
        let addr = format!("{host}:0");
        // Try to bind to the port
        if let Ok(listener) = TcpListener::bind(&addr).await {
            // Use test_config directory for tests
            let config_dir = PathBuf::from("test_config");
            let port = listener.local_addr()?.port();
            let server = Server::new(Cli {
                host,
                port: NonZeroU16::try_from(port).expect("Port 0 is non-zero"),
                root_dir,
                config_dir,
                require_signature: false, // Don't require signatures in test mode
                region: "crabcakes".to_string(), // Use default region for tests
                tls_cert: None,           // No TLS cert in test mode
                tls_key: None,            // No TLS key in test mode
            });
            return Ok((server, port));
        }

        Err(CrabCakesError::Other(
            "Could not find an available port for testing".to_string(),
        ))
    }

    pub async fn run(self) -> Result<(), CrabCakesError> {
        let addr: SocketAddr = format!("{}:{}", self.host, self.port).parse()?;

        // Create filesystem service
        let filesystem = Arc::new(FilesystemService::new(self.root_dir.clone()));

        // Derive policy and credential paths from config_dir
        let policy_dir = self.config_dir.join("policies");
        let credentials_dir = self.config_dir.join("credentials");

        // Load IAM policies
        let policy_store = Arc::new(PolicyStore::new(policy_dir.clone())?);

        // Load credentials
        let credentials_store = Arc::new(CredentialStore::new(credentials_dir.clone())?);

        if self.tls_cert.is_some() {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }

        // Create S3 handler
        let s3_handler: Arc<S3Handler> = Arc::new(S3Handler::new(
            filesystem,
            policy_store,
            credentials_store,
            self.region.clone(),
            self.require_signature,
            addr.to_string(),
        ));

        info!(
            root_dir = ?self.root_dir,
            config_dir = ?self.config_dir,
            policy_dir = ?policy_dir,
            credentials_dir = ?credentials_dir,
            region = %self.region,
            require_signature = %self.require_signature,
            address = %addr,
            "Starting crabcakes..."
        );

        let listener = TcpListener::bind(addr).await?;

        info!(
            "Server listening on http{}://{}",
            if self.tls_cert.is_some() && self.tls_key.is_some() {
                "s"
            } else {
                ""
            },
            addr
        );

        match (self.tls_cert.is_some(), self.tls_key.is_some()) {
            (true, true) => {
                let certs = self.load_cert()?;
                let key = self.load_private_key()?;

                let mut tls_server_config = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)?;
                tls_server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                let tls_acceptor = TlsAcceptor::from(Arc::new(tls_server_config));

                loop {
                    let (stream, remote_addr) = listener.accept().await?;
                    let tls_acceptor = tls_acceptor.clone();
                    debug!(remote_addr = %remote_addr, "Accepted new connection");

                    let handler = s3_handler.clone();
                    tokio::task::spawn(async move {
                        let tls_stream = match tls_acceptor.accept(stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                error!(error = %e, remote_addr = %remote_addr, "TLS handshake failed");
                                return;
                            }
                        };
                        if let Err(err) = Builder::new(TokioExecutor::new())
                            .serve_connection(
                                TokioIo::new(tls_stream),
                                service_fn(move |req| {
                                    let handler = Arc::clone(&handler);
                                    async move { handler.handle_request(req).await }
                                }),
                            )
                            .await
                        {
                            error!(error = %err, remote_addr = %remote_addr, "Error serving connection");
                        }
                    });
                }
            }
            (true, false) | (false, true) => {
                error!("Both TLS certificate and key must be provided to enable TLS");
                Err(CrabCakesError::other(
                    "Both TLS certificate and key must be provided to enable TLS",
                ))
            }
            (false, false) => loop {
                let (stream, remote_addr) = listener.accept().await?;
                debug!(remote_addr = %remote_addr, "Accepted new connection");

                let io = TokioIo::new(stream);
                let handler = s3_handler.clone();

                tokio::task::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(
                            io,
                            service_fn(move |req| {
                                let handler = Arc::clone(&handler);
                                async move { handler.handle_request(req).await }
                            }),
                        )
                        .await
                    {
                        error!(error = %err, remote_addr = %remote_addr, "Error serving connection");
                    }
                });
            },
        }
    }

    // Load public certificate from file.
    fn load_cert(&self) -> Result<Vec<CertificateDer<'static>>, CrabCakesError> {
        // Open certificate file.
        if let Some(cert_file) = self.tls_cert.as_ref() {
            let certfile = File::open(cert_file)?;
            let mut reader = BufReader::new(certfile);

            // Load and return certificate.
            rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| CrabCakesError::Other(format!("Failed to load certificates: {}", e)))
        } else {
            Ok(vec![])
        }
    }

    // Load private key from file.
    fn load_private_key(&self) -> Result<PrivateKeyDer<'static>, CrabCakesError> {
        // Open keyfile.
        if let Some(key_file) = self.tls_key.as_ref() {
            let keyfile = File::open(key_file)?;
            let mut reader = BufReader::new(keyfile);

            // Load and return a single private key.
            match rustls_pemfile::private_key(&mut reader) {
                Ok(Some(key)) => Ok(key),
                Ok(_) => Err(CrabCakesError::Other(
                    "No private keys found in the key file".to_string(),
                )),
                Err(e) => Err(CrabCakesError::Other(format!(
                    "Failed to load private key: {}",
                    e
                ))),
            }
        } else {
            Err(CrabCakesError::Other(
                "TLS key file not specified".to_string(),
            ))
        }
    }
}
