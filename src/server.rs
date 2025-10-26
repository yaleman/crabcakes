//! HTTP/HTTPS server setup and lifecycle management.
//!
//! Configures and runs the S3-compatible server with optional TLS support
//! and dynamic worker thread allocation.

use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::BufReader;
use tokio::fs::File;
use tower_http::trace::TraceLayer;

use tokio::net::TcpListener;
use tokio::sync::RwLock;
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
use crate::logging::LoggingSpanner;
use crate::multipart::MultipartManager;
use crate::policy::PolicyStore;
use crate::router::route_request;
use crate::web::handlers::WebHandler;
use crate::web::s3_handlers::S3Handler;
use crate::web::service::WebService;

/// Main server struct holding configuration and state, if oidc is not configured the admin interface won't be either.
pub struct Server {
    bind_address: String,
    port: NonZeroU16,
    root_dir: PathBuf,
    config_dir: PathBuf,
    region: String,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,

    oidc_client_id: Option<String>,
    oidc_discovery_url: Option<String>,
    frontend_url: Option<String>,
    #[cfg(test)]
    #[allow(dead_code)]
    disable_api: bool,
}

impl Server {
    pub fn new(cli: Cli) -> Self {
        Self {
            bind_address: cli.host,
            port: cli.port,
            root_dir: cli.root_dir,
            config_dir: cli.config_dir,
            region: cli.region,
            tls_cert: cli.tls_cert,
            tls_key: cli.tls_key,
            oidc_client_id: cli.oidc_client_id,
            oidc_discovery_url: cli.oidc_discovery_url,
            frontend_url: cli
                .frontend_url
                .map(|url| url.trim_end_matches('/').to_string()),
            #[cfg(test)]
            disable_api: cli.disable_api,
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
            use crate::constants::DEFAULT_REGION;

            let port = listener.local_addr()?.port();
            let server = Server::new(Cli {
                host,
                port: NonZeroU16::try_from(port).map_err(|_| {
                    CrabCakesError::Other(format!("Failed to convert port '{port}' to NonZeroU16",))
                })?,
                root_dir,
                config_dir,
                region: DEFAULT_REGION.to_string(), // Use default region for tests
                tls_cert: None,                     // No TLS cert in test mode
                tls_key: None,                      // No TLS key in test mode
                disable_api: true,                  // Disable API in test mode
                oidc_client_id: None,               // No OIDC in test mode
                oidc_discovery_url: None,           // No OIDC in test mode
                frontend_url: None,                 // No frontend URL in test mode
            });
            return Ok((server, port));
        }

        Err(CrabCakesError::Other(
            "Could not find an available port for testing".to_string(),
        ))
    }

    pub async fn run(self, use_in_memory_db: bool) -> Result<(), CrabCakesError> {
        let addr = format!("{}:{}", self.bind_address, self.port);
        let addr: SocketAddr = addr.parse().map_err(|err| {
            CrabCakesError::Configuration(format!("Failed to parse address '{addr}': {err}"))
        })?;
        // Create filesystem service
        let filesystem = Arc::new(FilesystemService::new(self.root_dir.clone())?);

        // Derive policy and credential paths from config_dir
        let policy_dir = self.config_dir.join("policies");
        let credentials_dir = self.config_dir.join("credentials");

        // Load IAM policies
        let policy_store = Arc::new(PolicyStore::new(&policy_dir).await?);

        // Load credentials
        let credentials_store = Arc::new(CredentialStore::new(&credentials_dir).await?);

        // Create multipart manager
        let multipart_manager = Arc::new(RwLock::new(MultipartManager::new(&self.root_dir)));

        // Initialize database and create DBService
        let db = if use_in_memory_db {
            #[cfg(test)]
            {
                initialize_in_memory_database().await
            }
            #[cfg(not(test))]
            {
                // In production builds, always use disk-based database
                initialize_database(&self.config_dir).await?
            }
        } else {
            initialize_database(&self.config_dir).await?
        };
        let db = Arc::new(db);

        let db_service = Arc::new(DBService::new(db.clone()));

        let fs_cleanup_task =
            crate::db::cleanup::TagCleaner::new(db.clone(), filesystem.clone(), Some(3600)); // Run every hour
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await; // Sleep for 30 seconds
                if let Err(e) = fs_cleanup_task.run().await {
                    error!(error=%e, "Filesystem cleanup task failed, sleeping for 30 seconds");
                };
            }
        });

        // Spawn background cleanup task for expired PKCE states and temporary credentials
        let db_cleanup_task = CleanupTask::new(db_service.clone(), 300); // Run every 5 minutes
        tokio::spawn(async move {
            db_cleanup_task.run().await;
        });

        if self.tls_cert.is_some() {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }

        // Create web service with session layer if OIDC is configured and API not disabled
        let web_service = {
            if let (Some(client_id), Some(discovery_url)) =
                (&self.oidc_client_id, &self.oidc_discovery_url)
            {
                let redirect_uri = if let Some(frontend_url) = &self.frontend_url {
                    format!("{}/oauth2/callback", frontend_url)
                } else {
                    format!(
                        "http{}://{}:{}/oauth2/callback",
                        if self.tls_cert.is_some() { "s" } else { "" },
                        self.bind_address,
                        self.port
                    )
                };
                let oauth_client = Arc::new(
                    OAuthClient::new(discovery_url, client_id, &redirect_uri, db_service.clone())
                        .await?,
                );

                // Create session store using the same SQLite database
                let session_db = db.clone();
                let session_store =
                    SqliteStore::new(session_db.get_sqlite_connection_pool().clone());
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

                let trace_layer = TraceLayer::new_for_http()
                    .make_span_with(LoggingSpanner::default())
                    .on_response(LoggingSpanner::default());

                let service_with_sessions = ServiceBuilder::new()
                    .layer(trace_layer)
                    .layer(session_layer)
                    .service(web_svc);

                // Box and clone the service for use in connection handlers
                Some(ServiceExt::boxed_clone(service_with_sessions))
            } else {
                info!("Web UI disabled: OIDC not configured");
                None
            }
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
        let listening_url = match &self.frontend_url.as_ref() {
            Some(val) => val,
            None => &format!(
                "http{}://{}:{}",
                if self.tls_cert.is_some() { "s" } else { "" },
                self.bind_address,
                self.port
            ),
        };
        info!(
            root_dir = ?self.root_dir,
            config_dir = ?self.config_dir,
            policy_dir = ?policy_dir,
            credentials_dir = ?credentials_dir,
            region = %self.region,
            address = %addr,
            frontend_url = %listening_url,
            tls_cert = ?self.tls_cert,
            tls_key = ?self.tls_key,
            "Starting crabcakes..."
        );

        let listener = TcpListener::bind(addr).await?;
        if self.tls_cert.is_some() && self.tls_key.is_none()
            || self.tls_cert.is_none() && self.tls_key.is_some()
        {
            error!(
                "Both TLS certificate and key must be provided to enable TLS. Starting server without TLS."
            );
        }

        info!("Starting server on {}...", listening_url);

        match self.tls_cert.is_some() && self.tls_key.is_some() {
            true => {
                let certs = self.load_cert().await.inspect_err(|e| {
                    error!(tls_cert = ?self.tls_cert, error = %e, "Failed to load TLS certificate");
                })?;
                let key = self.load_private_key().await.inspect_err(|e| {
                    error!(tls_key = ?self.tls_key, error = %e, "Failed to load TLS private key");
                })?;

                let mut tls_server_config = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .inspect_err(|err| error!(error=?err, "Failed to configure TLS server"))?;
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
                        // Use auto builder to support both HTTP/1.1 and HTTP/2
                        if let Err(err) = auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                            .serve_connection(
                                TokioIo::new(tls_stream),
                                service_fn(move |req| {
                                    let s3_handler = s3_handler.clone();
                                    let web_service = web_service.clone();
                                    async move {
                                        route_request(req, remote_addr, s3_handler, web_service)
                                            .await
                                    }
                                }),
                            )
                            .await
                        {
                            debug!(error = %err, remote_addr = %remote_addr, "Error serving connection");
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
                        debug!(error = %err, remote_addr = %remote_addr, "Error serving connection");
                    }
                });
            },
        }
    }

    // Load public certificate from file.
    async fn load_cert(&self) -> Result<Vec<CertificateDer<'static>>, CrabCakesError> {
        // Open certificate file.
        if let Some(cert_file) = self.tls_cert.as_ref() {
            let certfile = File::open(cert_file).await?;
            let mut reader = BufReader::new(certfile.into_std().await);
            // Load and return certificate.
            rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| CrabCakesError::Other(format!("Failed to load certificates: {}", e)))
        } else {
            Ok(vec![])
        }
    }

    // Load private key from file.
    async fn load_private_key(&self) -> Result<PrivateKeyDer<'static>, CrabCakesError> {
        // Open keyfile.
        if let Some(key_file) = self.tls_key.as_ref() {
            let keyfile = File::open(key_file).await?;
            let mut reader = BufReader::new(keyfile.into_std().await);

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
