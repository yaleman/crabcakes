//! OIDC/OAuth2 client with PKCE support

use std::sync::Arc;

use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
};
use reqwest;
use tokio::sync::RwLock;
use tracing::{debug, error, trace};

use crate::db::DBService;
use crate::error::CrabCakesError;

/// OAuth client for OIDC authentication with PKCE
pub struct OAuthClient {
    // TODO: make this an optional thing to support the delayed task/retries
    provider_metadata: Arc<RwLock<CoreProviderMetadata>>,
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
        // TODO: make this a delayed task that can retry
        let provider_metadata = Arc::new(RwLock::new( CoreProviderMetadata::discover_async(
            issuer_url.clone(),
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
                    let mut res = http::Response::new(body);
                    *res.status_mut() = status;
                    Ok(res)

                }
            }),
        )
        .await
        .map_err(|e: openidconnect::DiscoveryError<reqwest::Error>| {
            CrabCakesError::OidcDiscovery(format!(
                "Failed to query OIDC provider, can't start up! error={e} issuer_url={issuer_url}",
            ))
        })?));

        let redirect_url = RedirectUrl::new(redirect_uri.to_string()).map_err(|e| {
            CrabCakesError::OidcDiscovery(format!("Invalid OIDC redirect URI: {}", e))
        })?;

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

        let provider_metadata = self.provider_metadata.read().await.clone();
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
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
        let expires_at = chrono::Utc::now()
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
        if pkce_state.expires_at < chrono::Utc::now() {
            self.db.delete_pkce_state(state).await?;
            return Err(CrabCakesError::OidcStateParameterExpired);
        }

        // Exchange code for tokens

        let provider_metadata = self.provider_metadata.read().await.clone();
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            self.client_id.clone(),
            None, // No client secret (public client with PKCE)
        )
        .set_redirect_uri(self.redirect_uri.clone());

        let pkce_verifier = PkceCodeVerifier::new(pkce_state.code_verifier.clone());

        debug!("Exchanging authorization code for tokens");
        debug!("Redirect URI: {}", self.redirect_uri.as_str());

        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .map_err(|e| CrabCakesError::other(&format!("Exchange code failed: {}", e)))?
            .set_pkce_verifier(pkce_verifier)
            .request_async(
                &(move |http_request: http::Request<Vec<u8>>| {
                    let http_client = self.http_client.clone();
                    async move {
                        let uri = http_request.uri().to_string();
                        let body = http_request.body();
                        trace!("Token request to: {}", uri);
                        trace!("Token request headers: {:?}", http_request.headers());
                        if let Ok(body_str) = String::from_utf8(body.clone()) {
                            trace!("Token request body: {}", body_str);
                        }

                        let response = http_client
                            .request(http_request.method().clone(), &uri)
                            .headers(http_request.headers().clone())
                            .body(http_request.into_body())
                            .send()
                            .await?;

                        let status = response.status();
                        debug!("Token response status: {}", status);
                        let body = response.bytes().await?.to_vec();
                        debug!("Token response body length: {} bytes", body.len());

                        if !status.is_success()
                        {
                            error!("Token endpoint error response body: '{}'", String::from_utf8(body.clone()).unwrap_or(format!("{:?}", body)));
                        }

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
                    error!("Token exchange error: {:?}", e);
                    error!("This usually means:");
                    error!("  1. Redirect URI mismatch - check that {} matches your OIDC provider configuration", self.redirect_uri.as_str());
                    error!("  2. Authorization code already used or expired");
                    error!("  3. OIDC provider requires client authentication (client_secret) - crabcakes only supports PKCE");
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
}
