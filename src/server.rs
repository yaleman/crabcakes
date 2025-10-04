//! HTTP/HTTPS server setup and lifecycle management.
//!
//! Configures and runs the S3-compatible server with optional TLS support
//! and dynamic worker thread allocation.

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
use tower::ServiceBuilder;
use tower::ServiceExt;
use tower_sessions::cookie::time::Duration;
use tower_sessions::{Expiry, SessionManagerLayer};
use tower_sessions_sqlx_store::SqliteStore;
use tracing::{debug, error, info};

use crate::auth::OAuthClient;
use crate::cleanup::CleanupTask;
use crate::cli::Cli;
use crate::credentials::CredentialStore;
#[cfg(test)]
use crate::db::initialize_in_memory_database;
use crate::db::{DBService, initialize_database};
use crate::error::CrabCakesError;
use crate::filesystem::FilesystemService;
use crate::multipart::MultipartManager;
use crate::policy::PolicyStore;
use crate::router::{WebServiceWithSession, route_request};
use crate::s3_handlers::S3Handler;
use crate::web_handlers::WebHandler;
use crate::web_service::WebService;

pub struct Server {
    hostname: String,
    host: String,
    port: NonZeroU16,
    root_dir: PathBuf,
    config_dir: PathBuf,
    region: String,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    #[allow(dead_code)] // Will be used when web UI is implemented
    disable_api: bool,
    #[allow(dead_code)] // Will be used when OIDC is implemented
    oidc_client_id: Option<String>,
    #[allow(dead_code)] // Will be used when OIDC is implemented
    oidc_discovery_url: Option<String>,
}

impl Server {
    pub fn new(cli: Cli) -> Self {
        Self {
            hostname: cli.hostname.unwrap_or(cli.host.clone()),
            host: cli.host,
            port: cli.port,
            root_dir: cli.root_dir,
            config_dir: cli.config_dir,
            region: cli.region,
            tls_cert: cli.tls_cert,
            tls_key: cli.tls_key,
            disable_api: cli.disable_api,
            oidc_client_id: cli.oidc_client_id,
            oidc_discovery_url: cli.oidc_discovery_url,
        }
    }

    #[cfg(test)]
    /// Create a server instance for testing that binds to a random available port
    pub(crate) async fn test_mode(
        root_dir: PathBuf,
        config_dir: PathBuf,
    ) -> Result<(Self, u16), CrabCakesError> {
        // Try to find an available port in the high port range
        let host = "127.0.0.1".to_string();
        let addr = format!("{host}:0");
        // Try to bind to the port
        if let Ok(listener) = TcpListener::bind(&addr).await {
            let port = listener.local_addr()?.port();
            let server = Server::new(Cli {
                hostname: None,
                host,
                port: NonZeroU16::try_from(port).map_err(|_| {
                    CrabCakesError::Other(format!("Failed to convert port '{port}' to NonZeroU16",))
                })?,
                root_dir,
                config_dir,
                region: "crabcakes".to_string(), // Use default region for tests
                tls_cert: None,                  // No TLS cert in test mode
                tls_key: None,                   // No TLS key in test mode
                disable_api: true,               // Disable API in test mode
                oidc_client_id: None,            // No OIDC in test mode
                oidc_discovery_url: None,        // No OIDC in test mode
            });
            return Ok((server, port));
        }

        Err(CrabCakesError::Other(
            "Could not find an available port for testing".to_string(),
        ))
    }

    pub async fn run(self, use_in_memory_db: bool) -> Result<(), CrabCakesError> {
        let addr = format!("{}:{}", self.host, self.port);
        let addr: SocketAddr = addr.parse()?;

        // Create filesystem service
        let filesystem = Arc::new(FilesystemService::new(self.root_dir.clone()));

        // Derive policy and credential paths from config_dir
        let policy_dir = self.config_dir.join("policies");
        let credentials_dir = self.config_dir.join("credentials");

        // Load IAM policies
        let policy_store = Arc::new(PolicyStore::new(&policy_dir)?);

        // Load credentials
        let credentials_store = Arc::new(CredentialStore::new(&credentials_dir)?);

        // Create multipart manager
        let multipart_manager = Arc::new(MultipartManager::new(&self.root_dir));

        // Initialize database and create DBService
        let db = if use_in_memory_db {
            #[cfg(test)]
            {
                initialize_in_memory_database().await?
            }
            #[cfg(not(test))]
            {
                // In production builds, always use disk-based database
                initialize_database(&self.config_dir).await?
            }
        } else {
            initialize_database(&self.config_dir).await?
        };
        let db_service = Arc::new(DBService::new(Arc::new(db)));

        // Spawn background cleanup task for expired PKCE states and temporary credentials
        let cleanup_task = CleanupTask::new(db_service.clone(), 300); // Run every 5 minutes
        tokio::spawn(async move {
            cleanup_task.run().await;
        });

        if self.tls_cert.is_some() {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }

        // Create web service with session layer if OIDC is configured and API not disabled
        let web_service: Option<WebServiceWithSession> = if !self.disable_api {
            if let (Some(client_id), Some(discovery_url)) =
                (&self.oidc_client_id, &self.oidc_discovery_url)
            {
                let redirect_uri = format!(
                    "http{}://{}:{}/oauth2/callback",
                    if self.tls_cert.is_some() { "s" } else { "" },
                    self.hostname,
                    self.port
                );
                let oauth_client = Arc::new(
                    OAuthClient::new(discovery_url, client_id, &redirect_uri, db_service.clone())
                        .await?,
                );

                // Create session store using the same SQLite database
                let db_path = self.config_dir.join("crabcakes.sqlite3");
                let session_store = SqliteStore::new(
                    sqlx::SqlitePool::connect(&format!("sqlite://{}?mode=rwc", db_path.display()))
                        .await
                        .map_err(|e| {
                            CrabCakesError::other(&format!(
                                "Failed to connect to session database: {}",
                                e
                            ))
                        })?,
                );
                session_store.migrate().await.map_err(|e| {
                    CrabCakesError::other(&format!("Failed to migrate session store: {}", e))
                })?;

                let session_layer = SessionManagerLayer::new(session_store)
                    .with_secure(self.tls_cert.is_some())
                    .with_expiry(Expiry::OnInactivity(Duration::seconds(8 * 3600))); // 8 hours

                let web_handler = Arc::new(WebHandler::new(
                    oauth_client,
                    db_service.clone(),
                    credentials_store.clone(),
                    policy_store.clone(),
                    filesystem.clone(),
                ));

                // Create the web service and wrap it with the session layer
                let web_svc = WebService::new(web_handler);
                let service_with_sessions =
                    ServiceBuilder::new().layer(session_layer).service(web_svc);

                // Box and clone the service for use in connection handlers
                Some(ServiceExt::boxed_clone(service_with_sessions))
            } else {
                info!("Web UI disabled: OIDC not configured");
                None
            }
        } else {
            info!("Web UI disabled via --disable-api flag");
            None
        };

        // Create S3 handler
        let s3_handler: Arc<S3Handler> = Arc::new(S3Handler::new(
            filesystem,
            policy_store.clone(),
            credentials_store.clone(),
            multipart_manager,
            db_service.clone(),
            self.region.clone(),
            addr.to_string(),
        ));

        info!(
            root_dir = ?self.root_dir,
            config_dir = ?self.config_dir,
            policy_dir = ?policy_dir,
            credentials_dir = ?credentials_dir,
            region = %self.region,
            address = %addr,
            "Starting crabcakes..."
        );

        let listener = TcpListener::bind(addr).await?;

        info!(
            "Server listening on http{}://{}{}",
            if self.tls_cert.is_some() && self.tls_key.is_some() {
                "s"
            } else {
                ""
            },
            self.hostname,
            if [80, 443].contains(&self.port.get()) {
                String::new()
            } else {
                format!(":{}", self.port.get())
            }
        );

        if self.tls_cert.is_some() && self.tls_key.is_none()
            || self.tls_cert.is_none() && self.tls_key.is_some()
        {
            error!(
                "Both TLS certificate and key must be provided to enable TLS. Starting server without TLS."
            );
        }

        match self.tls_cert.is_some() && self.tls_key.is_some() {
            true => {
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

                    let s3_handler = s3_handler.clone();
                    let web_service = web_service.clone();

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
                                    let s3_handler = Arc::clone(&s3_handler);
                                    let web_service = web_service.clone();
                                    async move {
                                        route_request(req, remote_addr, s3_handler, web_service)
                                            .await
                                    }
                                }),
                            )
                            .await
                        {
                            error!(error = %err, remote_addr = %remote_addr, "Error serving connection");
                        }
                    });
                }
            }
            false => loop {
                let (stream, remote_addr) = listener.accept().await?;
                debug!(remote_addr = %remote_addr, "Accepted new connection");

                let io = TokioIo::new(stream);
                let s3_handler = s3_handler.clone();
                let web_service = web_service.clone();

                tokio::task::spawn(async move {
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(
                            io,
                            service_fn(move |req| {
                                let s3_handler = Arc::clone(&s3_handler);
                                let web_service = web_service.clone();
                                async move {
                                    route_request(req, remote_addr, s3_handler, web_service).await
                                }
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
            Err(CrabCakesError::Configuration(
                "TLS key file not specified".to_string(),
            ))
        }
    }
}
