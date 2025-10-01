use clap::Parser;
use crabcakes::cli::Cli;
use crabcakes::server::Server;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize tracing subscriber
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "crabcakes=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    let server = Server::new(
        cli.host,
        cli.port.get(),
        cli.root_dir,
        cli.config_dir,
        cli.require_signature,
        cli.region,
    );
    server.run().await.map_err(|err| {
        eprintln!("Server error: {}", err);
        err.into()
    })
}
