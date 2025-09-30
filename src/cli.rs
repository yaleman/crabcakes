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

    #[clap(
        short,
        long,
        default_value = "./policies",
        env = "CRABCAKES_POLICY_DIR"
    )]
    pub policy_dir: PathBuf,

    #[clap(
        short,
        long,
        default_value = "./credentials",
        env = "CRABCAKES_CREDENTIALS_DIR"
    )]
    pub credentials_dir: PathBuf,

    #[clap(long, default_value = "true", env = "CRABCAKES_REQUIRE_SIGNATURE")]
    pub require_signature: bool,
}
