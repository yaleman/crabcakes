use std::num::NonZeroU16;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
pub struct Cli {
    #[clap(short, long, default_value = "8090", env = "CRABCAKES_PORT")]
    pub port: NonZeroU16,

    #[clap(long, default_value = "127.0.0.1", env = "CRABCAKES_HOST")]
    pub host: String,

    #[clap(short, long, default_value = "./data", env = "CRABCAKES_ROOT_DIR")]
    pub root_dir: PathBuf,

    #[clap(short, long, default_value = "./config", env = "CRABCAKES_CONFIG_DIR")]
    pub config_dir: PathBuf,

    #[clap(long, default_value = "true", env = "CRABCAKES_REQUIRE_SIGNATURE")]
    pub require_signature: bool,

    #[clap(long, default_value = "crabcakes", env = "CRABCAKES_REGION")]
    pub region: String,
}
