//! Web UI and API handlers
//!
//! Handles authentication and API endpoints for the admin web interface.

use std::convert::Infallible;
use std::sync::Arc;

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
        _session: Session,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let method = req.method().clone();
        let path = req.uri().path();

        let result = match (method.as_str(), path) {
            ("GET", "/login") => self.handle_login().await,
            ("GET", path) if path.starts_with("/oauth2/callback") => {
                self.handle_oauth_callback(req).await
            }
            ("POST", "/logout") => self.handle_logout().await,
            ("GET", "/api/session") => self.handle_get_session().await,
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
        _req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // TODO: Extract code and state from query params
        // TODO: Exchange code for tokens
        // TODO: Create session
        // TODO: Generate temp credentials
        Err(CrabCakesError::other(
            &"OAuth callback not yet implemented".to_string(),
        ))
    }

    /// POST /logout - Delete session and credentials
    async fn handle_logout(&self) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // TODO: Get session ID from cookie
        // TODO: Delete temp credentials
        // TODO: Delete session
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Full::new(Bytes::new()))
            .map_err(CrabCakesError::from)
    }

    /// GET /api/session - Return session info with temp credentials
    async fn handle_get_session(&self) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // TODO: Get session from cookie
        // TODO: Look up temp credentials
        // TODO: Return session info as JSON
        Err(CrabCakesError::other(
            &"Session endpoint not yet implemented".to_string(),
        ))
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
