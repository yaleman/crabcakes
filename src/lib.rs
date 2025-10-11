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

use rand::Rng;

pub mod auth;
pub mod body_buffer;
pub mod cleanup;
pub mod cli;
pub mod constants;
pub mod credentials;
pub mod db;
pub mod error;
pub mod filesystem;
pub mod logging;
pub mod multipart;
pub mod policy;
pub mod policy_analyzer;
pub mod router;
pub mod s3_handlers;
pub mod server;
pub mod web;
pub mod xml_responses;

#[cfg(test)]
mod tests;

pub(crate) fn generate_temp_credentials() -> (String, String) {
    let mut rng = rand::rng();

    // Generate random access key (20 chars, alphanumeric)
    let access_key_id: String = (0..20)
        .map(|_| {
            let idx = rng.random_range(0..62);
            match idx {
                0..=25 => (b'A' + idx) as char,
                26..=51 => (b'a' + (idx - 26)) as char,
                _ => (b'0' + (idx - 52)) as char,
            }
        })
        .collect();

    // Generate random secret key (40 chars, alphanumeric + special)
    let secret_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let secret_access_key: String = (0..40)
        .map(|_| {
            let idx = rng.random_range(0..secret_chars.len());
            secret_chars[idx] as char
        })
        .collect();

    (access_key_id, secret_access_key)
}
