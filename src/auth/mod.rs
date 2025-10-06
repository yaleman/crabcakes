//! Authentication and authorization
//!
//! Provides AWS Signature V4 authentication for S3 operations and
//! OIDC/OAuth2 with PKCE authentication for the web admin interface.

pub mod oauth;
pub mod sigv4;

pub use oauth::OAuthClient;
pub use sigv4::{
    AuthContext, VerifiedRequest, extract_bucket_and_key, http_method_to_s3_action,
    sigv4_validate_streaming_request, verify_sigv4,
};
