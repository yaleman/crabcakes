//! Web UI and API handlers
//!
//! Handles authentication and API endpoints for the admin web interface.

use std::convert::Infallible;
use std::sync::Arc;

use form_urlencoded;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;

use crate::auth::OAuthClient;
use crate::credentials::CredentialStore;
use crate::db::DBService;
use crate::error::CrabCakesError;
use crate::policy::PolicyStore;

/// Web handler for admin UI and API endpoints
pub struct WebHandler {
    oauth_client: Arc<OAuthClient>,
    #[allow(dead_code)] // Will be used for session/credential lookups
    db: Arc<DBService>,
    #[allow(dead_code)] // Will be used for API endpoints
    credentials_store: Arc<CredentialStore>,
    #[allow(dead_code)] // Will be used for API endpoints
    policy_store: Arc<PolicyStore>,
}

impl WebHandler {
    pub fn new(
        oauth_client: Arc<OAuthClient>,
        db: Arc<DBService>,
        credentials_store: Arc<CredentialStore>,
        policy_store: Arc<PolicyStore>,
    ) -> Self {
        Self {
            oauth_client,
            db,
            credentials_store,
            policy_store,
        }
    }

    /// Main request handler - routes to appropriate endpoint
    pub async fn handle_request(
        &self,
        req: Request<hyper::body::Incoming>,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let method = req.method().clone();
        let path = req.uri().path();

        let result = match (method.as_str(), path) {
            ("GET", "/login") => self.handle_login().await,
            ("GET", path) if path.starts_with("/oauth2/callback") => {
                self.handle_oauth_callback(req, session.clone()).await
            }
            ("POST", "/logout") => self.handle_logout(session.clone()).await,
            ("GET", "/api/session") => self.handle_get_session(session.clone()).await,
            _ => self.not_found().await,
        };

        match result {
            Ok(resp) => Ok(resp),
            Err(e) => Ok(self.error_response(&e)),
        }
    }

    /// GET /login - Redirect to OIDC provider
    async fn handle_login(&self) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        let (auth_url, _state) = self.oauth_client.generate_auth_url().await?;

        Response::builder()
            .status(StatusCode::FOUND)
            .header("Location", auth_url)
            .body(Full::new(Bytes::new()))
            .map_err(CrabCakesError::from)
    }

    /// GET /oauth2/callback - Handle OAuth callback
    async fn handle_oauth_callback(
        &self,
        req: Request<hyper::body::Incoming>,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Extract query parameters
        let query = req.uri().query().ok_or_else(|| {
            CrabCakesError::other(&"Missing query parameters in OAuth callback".to_string())
        })?;

        // Parse query string for code and state
        let params: std::collections::HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();

        let code = params.get("code").ok_or_else(|| {
            CrabCakesError::other(&"Missing 'code' parameter in OAuth callback".to_string())
        })?;

        let state = params.get("state").ok_or_else(|| {
            CrabCakesError::other(&"Missing 'state' parameter in OAuth callback".to_string())
        })?;

        // Exchange code for tokens and get user info
        let (user_email, user_id) = self.oauth_client.exchange_code(code, state).await?;

        // Generate temporary AWS credentials
        let (access_key_id, secret_access_key) = self.oauth_client.generate_temp_credentials();

        // Set credentials to expire in 8 hours
        let expires_at = chrono::Utc::now().naive_utc()
            + chrono::Duration::try_hours(8).ok_or_else(|| {
                CrabCakesError::other(&"Failed to create credential expiry duration".to_string())
            })?;

        // Store session data
        session
            .insert("user_email", user_email.clone())
            .await
            .map_err(|e| CrabCakesError::other(&format!("Failed to store user_email in session: {}", e)))?;
        session
            .insert("user_id", user_id.clone())
            .await
            .map_err(|e| CrabCakesError::other(&format!("Failed to store user_id in session: {}", e)))?;
        session
            .insert("access_key_id", access_key_id.clone())
            .await
            .map_err(|e| CrabCakesError::other(&format!("Failed to store access_key_id in session: {}", e)))?;

        // Get session ID
        let session_id = session.id().map(|id| id.to_string()).ok_or_else(|| {
            CrabCakesError::other(&"Failed to get session ID".to_string())
        })?;

        // Store temporary credentials in database
        self.db
            .store_temporary_credentials(
                &access_key_id,
                &secret_access_key,
                &session_id,
                &user_email,
                &user_id,
                expires_at,
            )
            .await?;

        // Redirect to admin UI
        Response::builder()
            .status(StatusCode::FOUND)
            .header("Location", "/admin/")
            .body(Full::new(Bytes::new()))
            .map_err(CrabCakesError::from)
    }

    /// POST /logout - Delete session and credentials
    async fn handle_logout(&self, session: Session) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Get session ID before destroying session
        if let Some(session_id) = session.id() {
            let session_id_str = session_id.to_string();

            // Delete all temporary credentials for this session
            self.db
                .delete_credentials_by_session(&session_id_str)
                .await?;
        }

        // Delete the session (clears cookie and session data)
        session
            .delete()
            .await
            .map_err(|e| CrabCakesError::other(&format!("Failed to delete session: {}", e)))?;

        // Redirect to login page
        Response::builder()
            .status(StatusCode::FOUND)
            .header("Location", "/login")
            .body(Full::new(Bytes::new()))
            .map_err(CrabCakesError::from)
    }

    /// GET /api/session - Return session info with temp credentials
    async fn handle_get_session(&self, session: Session) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Get user info from session
        let user_email: String = session
            .get("user_email")
            .await
            .map_err(|e| CrabCakesError::other(&format!("Failed to get user_email from session: {}", e)))?
            .ok_or_else(|| CrabCakesError::other(&"Not authenticated".to_string()))?;

        let user_id: String = session
            .get("user_id")
            .await
            .map_err(|e| CrabCakesError::other(&format!("Failed to get user_id from session: {}", e)))?
            .ok_or_else(|| CrabCakesError::other(&"Not authenticated".to_string()))?;

        let access_key_id: String = session
            .get("access_key_id")
            .await
            .map_err(|e| CrabCakesError::other(&format!("Failed to get access_key_id from session: {}", e)))?
            .ok_or_else(|| CrabCakesError::other(&"Not authenticated".to_string()))?;

        // Look up credentials in database to get secret key and expiry
        let creds = self
            .db
            .get_temporary_credentials(&access_key_id)
            .await?
            .ok_or_else(|| CrabCakesError::other(&"Credentials not found or expired".to_string()))?;

        // Check if credentials are expired
        if creds.expires_at < chrono::Utc::now().naive_utc() {
            return Err(CrabCakesError::other(&"Credentials expired".to_string()));
        }

        // Build session info response
        let session_info = SessionInfo {
            user_email,
            user_id,
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            expires_at: creds.expires_at.to_string(),
        };

        // Return JSON response
        let json = serde_json::to_string(&session_info)?;
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(json)))
            .map_err(CrabCakesError::from)
    }

    /// 404 Not Found response
    async fn not_found(&self) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))
            .map_err(CrabCakesError::from)
    }

    /// Error response
    fn error_response(&self, error: &CrabCakesError) -> Response<Full<Bytes>> {
        let error_body = Full::new(Bytes::from(format!("Error: {}", error)));
        let mut response = Response::new(error_body);
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        response
    }
}

/// Session info returned to client
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub user_email: String,
    pub user_id: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub expires_at: String,
}
