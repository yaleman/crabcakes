use clap::Parser;
use crabcakes::cli::Cli;
use crabcakes::server::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    let server = Server::new(cli.host, cli.port.get(), cli.root_dir);
    server.run().await
}
