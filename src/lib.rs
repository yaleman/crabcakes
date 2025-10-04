//! Crabcakes - An S3-compatible server written in Rust.
//!
//! A filesystem-backed S3-compatible server with AWS Signature V4 authentication,
//! IAM policy-based authorization, and support for streaming uploads.

#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

pub mod async_spooled_tempfile;
pub mod auth;
pub mod body_buffer;
pub mod cleanup;
pub mod cli;
pub mod credentials;
pub mod db;
pub mod error;
pub mod filesystem;
pub mod multipart;
pub mod policy;
pub mod router;
pub mod s3_handlers;
pub mod server;
pub mod web_handlers;
pub mod xml_responses;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub fn setup_test_logging() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_test_writer()
                .with_level(true),
        )
        .with(tracing_subscriber::EnvFilter::new("debug,russh::client=info,russh::sshbuffer=info,russh::keys::agent::client=info,russh::keys::agent=info"))
        .try_init();
}
