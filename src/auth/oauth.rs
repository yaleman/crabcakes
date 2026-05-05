//! OIDC/OAuth2 client with PKCE support

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClaimsVerificationError, ClientId, CsrfToken, IssuerUrl,
    Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
    core::{CoreClient, CoreIdToken, CoreIdTokenClaims, CoreProviderMetadata, CoreResponseType},
};
use reqwest;
use tokio::sync::RwLock;
use tracing::{debug, error, trace};

use crate::db::DBService;
use crate::error::CrabCakesError;

const OIDC_METADATA_MAX_AGE: chrono::Duration = chrono::Duration::hours(24);

type ProviderMetadataDiscoveryResult =
    Result<CoreProviderMetadata, openidconnect::DiscoveryError<reqwest::Error>>;
type ProviderMetadataDiscoveryFuture =
    Pin<Box<dyn Future<Output = ProviderMetadataDiscoveryResult> + Send>>;
type ProviderMetadataDiscoverer =
    Arc<dyn Fn(IssuerUrl, reqwest::Client) -> ProviderMetadataDiscoveryFuture + Send + Sync>;

#[derive(Clone)]
struct CachedProviderMetadata {
    provider_metadata: CoreProviderMetadata,
    fetched_at: DateTime<Utc>,
}

impl CachedProviderMetadata {
    fn is_fresh_at(&self, now: DateTime<Utc>) -> bool {
        metadata_is_fresh_at(self.fetched_at, now)
    }
}

fn metadata_is_fresh_at(fetched_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    now.signed_duration_since(fetched_at) < OIDC_METADATA_MAX_AGE
}

fn default_provider_metadata_discoverer() -> ProviderMetadataDiscoverer {
    Arc::new(|issuer_url, http_client| Box::pin(run_discovery(issuer_url, http_client)))
}

async fn run_discovery(
    issuer_url: IssuerUrl,
    http_client: reqwest::Client,
) -> Result<CoreProviderMetadata, openidconnect::DiscoveryError<reqwest::Error>> {
    CoreProviderMetadata::discover_async(
        issuer_url,
        &(move |http_request: http::Request<Vec<u8>>| {
            let http_client = http_client.clone();
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
}

/// OAuth client for OIDC authentication with PKCE
pub struct OAuthClient {
    provider_metadata: Arc<RwLock<Option<CachedProviderMetadata>>>,
    client_id: ClientId,
    redirect_uri: RedirectUrl,
    db: Arc<DBService>,
    http_client: reqwest::Client,
    issuer_url: IssuerUrl,
    provider_metadata_discoverer: ProviderMetadataDiscoverer,
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
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| CrabCakesError::Reqwest(format!("Failed to create HTTP client: {}", e)))?;

        let issuer_url = IssuerUrl::new(discovery_url.to_string())
            .map_err(|e| CrabCakesError::other(&format!("Invalid OIDC issuer URL: {}", e)))?;

        let provider_metadata_discoverer = default_provider_metadata_discoverer();
        let http_client_clone = http_client.clone();
        // TODO: make this a delayed task that can retry
        let provider_metadata =
            match provider_metadata_discoverer(issuer_url.clone(), http_client_clone).await {
                Ok(pm) => Arc::new(RwLock::new(Some(CachedProviderMetadata {
                    provider_metadata: pm,
                    fetched_at: Utc::now(),
                }))),
                Err(err) => {
                    error!(error=%err, "Failed to run OIDC discovery");
                    // TODO: this should spawn a task to retry discovery every 30 seconds
                    Arc::new(RwLock::new(None))
                }
            };

        let redirect_url = RedirectUrl::new(redirect_uri.to_string()).map_err(|e| {
            CrabCakesError::OidcDiscovery(format!("Invalid OIDC redirect URI: {}", e))
        })?;

        Ok(Self {
            provider_metadata,
            client_id: ClientId::new(client_id.to_string()),
            redirect_uri: redirect_url,
            db,
            http_client,
            issuer_url,
            provider_metadata_discoverer,
        })
    }

    async fn get_provider_metadata(&self) -> Result<CoreProviderMetadata, CrabCakesError> {
        if let Some(cached_provider_metadata) = self.provider_metadata.read().await.clone() {
            if cached_provider_metadata.is_fresh_at(Utc::now()) {
                return Ok(cached_provider_metadata.provider_metadata);
            }

            debug!("OIDC provider metadata is older than 24 hours; refreshing");
        }

        self.refresh_provider_metadata().await
    }

    async fn refresh_provider_metadata(&self) -> Result<CoreProviderMetadata, CrabCakesError> {
        let pm = self.provider_metadata_discoverer.as_ref()(
            self.issuer_url.clone(),
            self.http_client.clone(),
        )
        .await
        .map_err(|err| {
            error!(error=?err, "Failed to run OIDC discovery");
            CrabCakesError::from(err)
        })?;

        self.provider_metadata
            .write()
            .await
            .replace(CachedProviderMetadata {
                provider_metadata: pm.clone(),
                fetched_at: Utc::now(),
            });
        Ok(pm)
    }

    fn validate_id_token_claims<'a>(
        &self,
        provider_metadata: CoreProviderMetadata,
        id_token: &'a CoreIdToken,
        nonce: &Nonce,
    ) -> Result<&'a CoreIdTokenClaims, ClaimsVerificationError> {
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            self.client_id.clone(),
            None, // No client secret (public client with PKCE)
        )
        .set_redirect_uri(self.redirect_uri.clone());

        id_token.claims(&client.id_token_verifier(), nonce)
    }

    async fn validate_with_metadata_refresh<T>(
        &self,
        provider_metadata: CoreProviderMetadata,
        validate: impl Fn(CoreProviderMetadata) -> Result<T, ClaimsVerificationError>,
    ) -> Result<T, CrabCakesError> {
        match validate(provider_metadata) {
            Ok(value) => Ok(value),
            Err(err) if Self::is_signature_validation_error(&err) => {
                error!(
                    error = %err,
                    "ID token signature validation failed; refreshing OIDC provider metadata and retrying"
                );
                let refreshed_provider_metadata = self.refresh_provider_metadata().await?;
                validate(refreshed_provider_metadata).map_err(|retry_err| {
                    CrabCakesError::other(&format!(
                        "ID token validation failed after OIDC metadata refresh: {}",
                        retry_err
                    ))
                })
            }
            Err(err) => Err(CrabCakesError::other(&format!(
                "ID token validation failed: {}",
                err
            ))),
        }
    }

    fn is_signature_validation_error(err: &ClaimsVerificationError) -> bool {
        matches!(err, ClaimsVerificationError::SignatureVerification(_))
    }

    /// Generate authorization URL with PKCE challenge
    /// Returns (auth_url, csrf_token/state)
    pub async fn generate_auth_url(&self) -> Result<(String, String), CrabCakesError> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let provider_metadata = self.get_provider_metadata().await?;
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

        let provider_metadata = self.get_provider_metadata().await?;
        let client = CoreClient::from_provider_metadata(
            provider_metadata.clone(),
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
        let claims = self
            .validate_with_metadata_refresh(provider_metadata, |metadata| {
                self.validate_id_token_claims(metadata, id_token, &nonce)
            })
            .await?;

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

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use openidconnect::{
        AuthUrl, JsonWebKeySetUrl, ResponseTypes, SignatureVerificationError,
        core::{CoreJwsSigningAlgorithm, CoreSubjectIdentifierType},
    };

    use super::*;
    use crate::db::{DBService, initialize_in_memory_database};

    fn test_provider_metadata(issuer: &str) -> CoreProviderMetadata {
        CoreProviderMetadata::new(
            IssuerUrl::new(issuer.to_string()).expect("issuer URL should be valid"),
            AuthUrl::new(format!("{issuer}/auth")).expect("auth URL should be valid"),
            JsonWebKeySetUrl::new(format!("{issuer}/jwks")).expect("JWKS URL should be valid"),
            vec![ResponseTypes::new(vec![CoreResponseType::Code])],
            vec![CoreSubjectIdentifierType::Public],
            vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
            Default::default(),
        )
    }

    fn discoverer_returning(
        provider_metadata: CoreProviderMetadata,
        calls: Arc<AtomicUsize>,
    ) -> ProviderMetadataDiscoverer {
        Arc::new(move |_issuer_url, _http_client| {
            calls.fetch_add(1, Ordering::SeqCst);
            let provider_metadata = provider_metadata.clone();
            Box::pin(async move { Ok(provider_metadata) })
        })
    }

    async fn test_client(
        provider_metadata: Option<CachedProviderMetadata>,
        provider_metadata_discoverer: ProviderMetadataDiscoverer,
    ) -> OAuthClient {
        let db = Arc::new(DBService::new(Arc::new(
            initialize_in_memory_database().await,
        )));
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .expect("HTTP client should build");

        OAuthClient {
            provider_metadata: Arc::new(RwLock::new(provider_metadata)),
            client_id: ClientId::new("test-client".to_string()),
            redirect_uri: RedirectUrl::new("https://app.example/oauth2/callback".to_string())
                .expect("redirect URI should be valid"),
            db,
            http_client,
            issuer_url: IssuerUrl::new("https://issuer.example".to_string())
                .expect("issuer URL should be valid"),
            provider_metadata_discoverer,
        }
    }

    #[test]
    fn metadata_younger_than_24_hours_is_fresh() {
        let now = Utc::now();

        assert!(metadata_is_fresh_at(now - chrono::Duration::hours(23), now));
    }

    #[test]
    fn metadata_24_hours_old_is_stale() {
        let now = Utc::now();

        assert!(!metadata_is_fresh_at(
            now - chrono::Duration::hours(24),
            now
        ));
    }

    #[tokio::test]
    async fn get_provider_metadata_reuses_fresh_cached_metadata() {
        let cached_metadata = test_provider_metadata("https://cached.example");
        let refresh_metadata = test_provider_metadata("https://refresh.example");
        let calls = Arc::new(AtomicUsize::new(0));
        let client = test_client(
            Some(CachedProviderMetadata {
                provider_metadata: cached_metadata.clone(),
                fetched_at: Utc::now(),
            }),
            discoverer_returning(refresh_metadata, calls.clone()),
        )
        .await;

        let provider_metadata = client
            .get_provider_metadata()
            .await
            .expect("fresh metadata should be returned");

        assert_eq!(provider_metadata.issuer(), cached_metadata.issuer());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn get_provider_metadata_refreshes_stale_cached_metadata() {
        let cached_metadata = test_provider_metadata("https://cached.example");
        let refresh_metadata = test_provider_metadata("https://refresh.example");
        let calls = Arc::new(AtomicUsize::new(0));
        let client = test_client(
            Some(CachedProviderMetadata {
                provider_metadata: cached_metadata,
                fetched_at: Utc::now() - chrono::Duration::hours(24),
            }),
            discoverer_returning(refresh_metadata.clone(), calls.clone()),
        )
        .await;

        let provider_metadata = client
            .get_provider_metadata()
            .await
            .expect("stale metadata should be refreshed");

        assert_eq!(provider_metadata.issuer(), refresh_metadata.issuer());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn signature_validation_error_refreshes_metadata_and_retries_once() {
        let initial_metadata = test_provider_metadata("https://initial.example");
        let refresh_metadata = test_provider_metadata("https://refresh.example");
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let validation_attempts = Arc::new(AtomicUsize::new(0));
        let client = test_client(
            Some(CachedProviderMetadata {
                provider_metadata: initial_metadata.clone(),
                fetched_at: Utc::now(),
            }),
            discoverer_returning(refresh_metadata.clone(), refresh_calls.clone()),
        )
        .await;

        let result = client
            .validate_with_metadata_refresh(initial_metadata.clone(), {
                let validation_attempts = validation_attempts.clone();
                move |provider_metadata| {
                    let attempt = validation_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                    if attempt == 1 {
                        assert_eq!(provider_metadata.issuer(), initial_metadata.issuer());
                        Err(ClaimsVerificationError::SignatureVerification(
                            SignatureVerificationError::NoMatchingKey,
                        ))
                    } else {
                        assert_eq!(provider_metadata.issuer(), refresh_metadata.issuer());
                        Ok(())
                    }
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(validation_attempts.load(Ordering::SeqCst), 2);
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn non_signature_validation_error_does_not_refresh_metadata() {
        let initial_metadata = test_provider_metadata("https://initial.example");
        let refresh_metadata = test_provider_metadata("https://refresh.example");
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let validation_attempts = Arc::new(AtomicUsize::new(0));
        let client = test_client(
            Some(CachedProviderMetadata {
                provider_metadata: initial_metadata.clone(),
                fetched_at: Utc::now(),
            }),
            discoverer_returning(refresh_metadata, refresh_calls.clone()),
        )
        .await;

        let result: Result<(), CrabCakesError> = client
            .validate_with_metadata_refresh(initial_metadata, {
                let validation_attempts = validation_attempts.clone();
                move |_provider_metadata| {
                    validation_attempts.fetch_add(1, Ordering::SeqCst);
                    Err(ClaimsVerificationError::InvalidNonce(
                        "bad nonce".to_string(),
                    ))
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(validation_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 0);
    }
}
