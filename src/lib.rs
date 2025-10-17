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

use crate::constants::TEMP_ACCESS_KEY_LENGTH;

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
pub mod request_handler;
pub mod router;
pub mod server;
pub mod web;

#[cfg(test)]
mod tests;

pub(crate) static AKID_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

pub(crate) static SECRET_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn generate_temp_credentials() -> (String, String) {
    let mut rng = rand::rng();

    // Generate random access key (20 chars, alphanumeric)
    let access_key_id = loop {
        let access_key_id: Vec<u8> = (0..TEMP_ACCESS_KEY_LENGTH - 4)
            .map(|_| AKID_CHARS[rng.random_range(0..AKID_CHARS.len())])
            .collect();

        if let Ok(s) = String::from_utf8(access_key_id) {
            break format!("temp{s}");
        }
    };

    // Generate random secret key (40 chars, alphanumeric + special)
    let secret_access_key: String = (0..40)
        .map(|_| {
            let idx = rng.random_range(0..SECRET_CHARS.len());
            SECRET_CHARS[idx] as char
        })
        .collect();

    (access_key_id, secret_access_key)
}
