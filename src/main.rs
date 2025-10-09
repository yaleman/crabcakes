//! Crabcakes - An S3-compatible server written in Rust.
//!
//! Main entry point that initializes tracing and starts the server.

use clap::Parser;
use crabcakes::cli::Cli;
use crabcakes::server::Server;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Calculate worker threads: num_cpus - 2, minimum of 4
    let worker_threads = std::cmp::max(num_cpus::get().saturating_sub(2), 4);

    // Build Tokio runtime with calculated worker threads
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?;

    runtime.block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize tracing subscriber
    let log_level = std::env::var("RUST_LOG").unwrap_or("info".to_string());
    let log_level_sqlx = std::env::var("RUST_LOG_SQLX").unwrap_or("warn".to_string());
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(format!(
            "crabcakes={log_level},scratchstack_aws_signature=debug,tower_http=info,h2=warn,sqlx={log_level_sqlx}",
        )))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let mut hangup_waiter = signal(SignalKind::hangup())?;
    loop {
        let cli = Cli::parse();
        let server = Server::new(cli);
        tokio::select! {
            res = server.run(false) => {
                if let Err(err) = res {
                    eprintln!("Server error: {}", err);
                    break
                };
            }
            _ = hangup_waiter.recv() => {
                warn!("Received SIGHUP, shutting down.");
                break
                // TODO: Implement configuration reload logic here

            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl-C, shutting down.");
                break
            }
        }
    }
    Ok(())
}
