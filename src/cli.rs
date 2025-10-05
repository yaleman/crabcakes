//! Command-line interface configuration.
//!
//! Defines CLI arguments and configuration loading from environment variables.

use std::num::NonZeroU16;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
pub struct Cli {
    #[clap(short, long, default_value = "9000", env = "CRABCAKES_PORT")]
    pub port: NonZeroU16,

    #[clap(long, default_value = "127.0.0.1", env = "CRABCAKES_LISTENER_ADDRESS")]
    pub host: String,

    #[clap(short, long, default_value = "./data", env = "CRABCAKES_ROOT_DIR")]
    pub root_dir: PathBuf,

    #[clap(short, long, default_value = "./config", env = "CRABCAKES_CONFIG_DIR")]
    pub config_dir: PathBuf,

    #[clap(long, default_value = "crabcakes", env = "CRABCAKES_REGION")]
    pub region: String,

    #[clap(long, env = "CRABCAKES_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,

    #[clap(long, env = "CRABCAKES_TLS_KEY")]
    pub tls_key: Option<PathBuf>,

    #[clap(
        long,
        env = "CRABCAKES_OIDC_CLIENT_ID",
        help = "OIDC client ID for OAuth2 authentication"
    )]
    pub oidc_client_id: Option<String>,

    #[clap(
        long,
        env = "CRABCAKES_OIDC_DISCOVERY_URL",
        help = "OIDC issuer URL (e.g., https://accounts.google.com). The .well-known/openid-configuration path is automatically appended during discovery."
    )]
    pub oidc_discovery_url: Option<String>,

    #[clap(
        long,
        env = "CRABCAKES_FRONTEND_URL",
        help = "Frontend URL for OIDC redirect URIs when behind a reverse proxy (e.g., https://example.com). If not set, uses http(s)://hostname:port"
    )]
    pub frontend_url: Option<String>,

    #[cfg(test)]
    pub(crate) disable_api: bool,
}
