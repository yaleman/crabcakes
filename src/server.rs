use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

use crate::filesystem::FilesystemService;
use crate::policy::PolicyStore;
use crate::s3_handlers::S3Handler;

pub struct Server {
    host: String,
    port: u16,
    root_dir: PathBuf,
    policy_dir: PathBuf,
}

impl Server {
    pub fn new(host: String, port: u16, root_dir: PathBuf, policy_dir: PathBuf) -> Self {
        Self {
            host,
            port,
            root_dir,
            policy_dir,
        }
    }

    /// Create a server instance for testing that binds to a random available port
    pub async fn test_mode(
        root_dir: PathBuf,
    ) -> Result<(Self, u16), Box<dyn std::error::Error + Send + Sync>> {
        // Try to find an available port in the high port range
        for _ in 0..10 {
            let port = rand::random::<u16>().saturating_add(10000);
            let addr = format!("127.0.0.1:{}", port);

            // Try to bind to the port
            if TcpListener::bind(&addr).await.is_ok() {
                // Use test_policies directory for tests
                let policy_dir = PathBuf::from("test_policies");
                let server = Self::new("127.0.0.1".to_string(), port, root_dir, policy_dir);
                return Ok((server, port));
            }
        }

        Err("Could not find an available port after 10 attempts".into())
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr: SocketAddr = format!("{}:{}", self.host, self.port).parse()?;

        // Create filesystem service
        let filesystem = Arc::new(FilesystemService::new(self.root_dir.clone()));

        // Load IAM policies
        let policy_store = match PolicyStore::new(self.policy_dir.clone()) {
            Ok(store) => Arc::new(store),
            Err(e) => {
                error!(error = %e, "Failed to load policies, starting without policy enforcement");
                Arc::new(PolicyStore::new(PathBuf::from("/nonexistent")).unwrap())
            }
        };

        // Create S3 handler
        let s3_handler = Arc::new(S3Handler::new(filesystem, policy_store));

        info!(
            root_dir = ?self.root_dir,
            policy_dir = ?self.policy_dir,
            address = %addr,
            "Starting S3 server"
        );

        let listener = TcpListener::bind(addr).await?;
        info!("Server listening on http://{}", addr);

        loop {
            let (stream, remote_addr) = listener.accept().await?;
            debug!(remote_addr = %remote_addr, "Accepted new connection");

            let io = TokioIo::new(stream);
            let handler = Arc::clone(&s3_handler);

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
        }
    }
}
