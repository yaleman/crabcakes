//! OIDC/OAuth2 client with PKCE support
//!
//! This module will provide OAuth2/OIDC authentication with PKCE for the admin UI.
//! Full implementation pending - currently a placeholder.

use std::sync::Arc;

use rand::Rng;

use crate::db::DBService;
use crate::error::CrabCakesError;

/// OAuth client for OIDC authentication with PKCE
pub struct OAuthClient {
    #[allow(dead_code)]
    db: Arc<DBService>,
    #[allow(dead_code)]
    redirect_uri: String,
    #[allow(dead_code)]
    client_id: String,
    #[allow(dead_code)]
    discovery_url: String,
}

impl OAuthClient {
    /// Create new OAuth client from OIDC discovery URL
    pub async fn new(
        discovery_url: &str,
        client_id: &str,
        redirect_uri: &str,
        db: Arc<DBService>,
    ) -> Result<Self, CrabCakesError> {
        Ok(Self {
            db,
            redirect_uri: redirect_uri.to_string(),
            client_id: client_id.to_string(),
            discovery_url: discovery_url.to_string(),
        })
    }

    /// Generate authorization URL with PKCE challenge
    /// Returns (auth_url, csrf_token/state)
    pub async fn generate_auth_url(&self) -> Result<(String, String), CrabCakesError> {
        // TODO: Implement full OIDC flow with PKCE
        Err(CrabCakesError::other(&"OAuth not yet implemented".to_string()))
    }

    /// Exchange authorization code for tokens and validate
    /// Returns (user_email, user_id)
    pub async fn exchange_code(
        &self,
        _code: &str,
        _state: &str,
    ) -> Result<(String, String), CrabCakesError> {
        // TODO: Implement token exchange
        Err(CrabCakesError::other(&"OAuth not yet implemented".to_string()))
    }

    /// Generate temporary AWS credentials
    /// Returns (access_key_id, secret_access_key)
    pub fn generate_temp_credentials(&self) -> (String, String) {
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
}
