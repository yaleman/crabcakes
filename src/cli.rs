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
}
