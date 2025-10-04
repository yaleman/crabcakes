//! OIDC/OAuth2 client with PKCE support

use std::sync::Arc;

use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
};
use rand::Rng;
use reqwest;
use tracing::debug;

use crate::db::DBService;
use crate::error::CrabCakesError;

/// OAuth client for OIDC authentication with PKCE
pub struct OAuthClient {
    provider_metadata: CoreProviderMetadata,
    client_id: ClientId,
    redirect_uri: RedirectUrl,
    db: Arc<DBService>,
    http_client: reqwest::Client,
}

impl OAuthClient {
    /// Create new OAuth client from OIDC discovery URL
    pub async fn new(
        discovery_url: &str,
        client_id: &str,
        redirect_uri: &str,
        db: Arc<DBService>,
    ) -> Result<Self, CrabCakesError> {
        // Create async HTTP client
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| CrabCakesError::Reqwest(format!("Failed to create HTTP client: {}", e)))?;

        let issuer_url = IssuerUrl::new(discovery_url.to_string())
            .map_err(|e| CrabCakesError::other(&format!("Invalid OIDC issuer URL: {}", e)))?;

        let http_client_clone = http_client.clone();
        let provider_metadata = CoreProviderMetadata::discover_async(
            issuer_url,
            &(move |http_request: http::Request<Vec<u8>>| {
                let http_client = http_client_clone.clone();
                async move {
                    let uri = http_request.uri().to_string();
                    let response = http_client
                        .request(http_request.method().clone(), &uri)
                        .headers(http_request.headers().clone())
                        .body(http_request.into_body())
                        .send()
                        .await?;

                    let status = response.status();
                    let body = response.bytes().await?.to_vec();

                    // This should never fail as we're providing valid status and body
                    Ok(http::Response::builder()
                        .status(status)
                        .body(body)
                        .unwrap_or_else(|_| {
                            // If Response::builder somehow fails (which should never happen),
                            // return a basic error response
                            http::Response::new(b"Internal Server Error".to_vec())
                        }))
                }
            }),
        )
        .await
        .map_err(|e: openidconnect::DiscoveryError<reqwest::Error>| {
            CrabCakesError::other(&format!("Failed to discover OIDC provider: {}", e))
        })?;

        let redirect_url = RedirectUrl::new(redirect_uri.to_string())
            .map_err(|e| CrabCakesError::other(&format!("Invalid OIDC redirect URI: {}", e)))?;

        Ok(Self {
            provider_metadata,
            client_id: ClientId::new(client_id.to_string()),
            redirect_uri: redirect_url,
            db,
            http_client,
        })
    }

    /// Generate authorization URL with PKCE challenge
    /// Returns (auth_url, csrf_token/state)
    pub async fn generate_auth_url(&self) -> Result<(String, String), CrabCakesError> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let client = CoreClient::from_provider_metadata(
            self.provider_metadata.clone(),
            self.client_id.clone(),
            None, // No client secret (public client with PKCE)
        )
        .set_redirect_uri(self.redirect_uri.clone());

        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .set_pkce_challenge(pkce_challenge.clone())
            .url();

        // Store PKCE state in database (expires in 10 minutes)
        let expires_at = chrono::Utc::now().naive_utc()
            + chrono::Duration::try_minutes(10).ok_or_else(|| {
                CrabCakesError::other(&"Failed to create PKCE session duration".to_string())
            })?;
        self.db
            .store_pkce_state(
                csrf_token.secret(),
                pkce_verifier.secret(),
                nonce.secret(),
                pkce_challenge.as_str(),
                self.redirect_uri.as_str(),
                expires_at,
            )
            .await?;

        Ok((auth_url.to_string(), csrf_token.secret().to_string()))
    }

    /// Exchange authorization code for tokens and validate
    /// Returns (user_email, user_id)
    pub async fn exchange_code(
        &self,
        code: &str,
        state: &str,
    ) -> Result<(String, String), CrabCakesError> {
        // Retrieve PKCE state from database
        let pkce_state = self
            .db
            .get_pkce_state(state)
            .await?
            .ok_or(CrabCakesError::OidcStateParameterExpired)?;

        // Check if expired
        if pkce_state.expires_at < chrono::Utc::now().naive_utc() {
            self.db.delete_pkce_state(state).await?;
            return Err(CrabCakesError::OidcStateParameterExpired);
        }

        // Exchange code for tokens
        let client = CoreClient::from_provider_metadata(
            self.provider_metadata.clone(),
            self.client_id.clone(),
            None, // No client secret (public client with PKCE)
        )
        .set_redirect_uri(self.redirect_uri.clone());

        let pkce_verifier = PkceCodeVerifier::new(pkce_state.code_verifier.clone());
        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .map_err(|e| CrabCakesError::other(&format!("Exchange code failed: {}", e)))?
            .set_pkce_verifier(pkce_verifier)
            .request_async(
                &(move |http_request: http::Request<Vec<u8>>| {
                    let http_client = self.http_client.clone();
                    async move {
                        let uri = http_request.uri().to_string();
                        let response = http_client
                            .request(http_request.method().clone(), &uri)
                            .headers(http_request.headers().clone())
                            .body(http_request.into_body())
                            .send()
                            .await?;

                        let status = response.status();
                        let body = response.bytes().await?.to_vec();

                        // This should never fail as we're providing valid status and body
                        Ok(http::Response::builder()
                            .status(status)
                            .body(body)
                            .unwrap_or_else(|_| {
                                // If Response::builder somehow fails (which should never happen),
                                // return a basic error response
                                http::Response::new(b"Internal Server Error".to_vec())
                            }))
                    }
                }),
            )
            .await
            .map_err(
                |e: openidconnect::RequestTokenError<
                    reqwest::Error,
                    openidconnect::StandardErrorResponse<
                        openidconnect::core::CoreErrorResponseType,
                    >,
                >| {
                    CrabCakesError::other(&format!("Token exchange failed: {}", e))
                },
            )?;

        // Verify ID token
        let id_token = token_response
            .id_token()
            .ok_or_else(|| CrabCakesError::other(&"No ID token in response".to_string()))?;

        let nonce = Nonce::new(pkce_state.nonce.clone());
        let claims = id_token
            .claims(&client.id_token_verifier(), &nonce)
            .map_err(|e| CrabCakesError::other(&format!("ID token validation failed: {}", e)))?;

        // Extract user info
        let user_email = claims
            .email()
            .map(|e| e.as_str())
            .ok_or_else(|| {
                debug!("ID token claims: {:?}", claims);
                CrabCakesError::other(&"Email address not found in ID token".to_string())
            })?
            .to_string();
        let user_id = claims.subject().as_str().to_string();

        // Clean up PKCE state
        self.db.delete_pkce_state(state).await?;

        Ok((user_email, user_id))
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
