//! Crabcakes - An S3-compatible server written in Rust.
//!
//! Main entry point that initializes tracing and starts the server.

use clap::Parser;
use crabcakes::server::Server;
use crabcakes::{cli::Cli, logging::setup_logging};
use tokio::signal::unix::{SignalKind, signal};
use tracing::{info, warn};

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Calculate worker threads: num_cpus, minimum of 4
    let worker_threads = std::cmp::max(num_cpus::get(), 4);

    // Build Tokio runtime with calculated worker threads
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?;

    runtime.block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    setup_logging();

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
