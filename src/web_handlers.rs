//! Web UI and API handlers
//!
//! Handles authentication and API endpoints for the admin web interface.

use std::convert::Infallible;
use std::sync::Arc;

use askama::Template;
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
use crate::filesystem::FilesystemService;
use crate::policy::PolicyStore;

/// Profile page template
#[derive(Template)]
#[template(path = "profile.html")]
struct ProfileTemplate {
    page: String,
    user_email: String,
    user_id: String,
    access_key_id: String,
    secret_key_preview: String,
    expires_at: String,
}

/// Policies list template
#[derive(Template)]
#[template(path = "policies.html")]
struct PoliciesTemplate {
    page: String,
    policies: Vec<PolicyInfo>,
}

/// Policy detail template
#[derive(Template)]
#[template(path = "policy_detail.html")]
struct PolicyDetailTemplate {
    page: String,
    policy_name: String,
    policy_json: String,
}

/// Credentials list template
#[derive(Template)]
#[template(path = "credentials.html")]
struct CredentialsTemplate {
    page: String,
    credentials: Vec<String>,
}

/// Buckets list template
#[derive(Template)]
#[template(path = "buckets.html")]
struct BucketsTemplate {
    page: String,
    buckets: Vec<String>,
}

/// Bucket detail template
#[derive(Template)]
#[template(path = "bucket_detail.html")]
struct BucketDetailTemplate {
    page: String,
    bucket_name: String,
    objects: Vec<ObjectInfo>,
}

/// Policy info for listing
#[derive(Debug)]
struct PolicyInfo {
    name: String,
    statement_count: usize,
}

/// Object info for bucket listing
#[derive(Debug)]
struct ObjectInfo {
    key: String,
    size_formatted: String,
    last_modified: String,
}

/// Web handler for admin UI and API endpoints
pub struct WebHandler {
    oauth_client: Arc<OAuthClient>,
    db: Arc<DBService>,
    credentials_store: Arc<CredentialStore>,
    policy_store: Arc<PolicyStore>,
    filesystem: Arc<FilesystemService>,
}

impl WebHandler {
    pub fn new(
        oauth_client: Arc<OAuthClient>,
        db: Arc<DBService>,
        credentials_store: Arc<CredentialStore>,
        policy_store: Arc<PolicyStore>,
        filesystem: Arc<FilesystemService>,
    ) -> Self {
        Self {
            oauth_client,
            db,
            credentials_store,
            policy_store,
            filesystem,
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
            ("GET", "/") => self.handle_root().await,
            ("GET", "/login") => self.handle_login().await,
            ("GET", path) if path.starts_with("/oauth2/callback") => {
                self.handle_oauth_callback(req, session.clone()).await
            }
            ("POST", "/logout") => self.handle_logout(session.clone()).await,
            ("GET", "/api/session") => self.handle_get_session(session.clone()).await,
            ("GET", "/admin/api/csrf-token") => self.handle_csrf_token(session.clone()).await,
            ("GET", "/admin") | ("GET", "/admin/") => self.handle_root().await,
            ("GET", "/admin/profile") => self.handle_profile(session.clone()).await,
            ("GET", "/admin/policies") => self.handle_policies(session.clone()).await,
            ("GET", path) if path.starts_with("/admin/policies/") => {
                let policy_name = path.strip_prefix("/admin/policies/").unwrap_or("");
                self.handle_policy_detail(session.clone(), policy_name)
                    .await
            }
            ("GET", "/admin/credentials") => self.handle_credentials(session.clone()).await,
            ("GET", "/admin/buckets") => self.handle_buckets(session.clone()).await,
            ("GET", path) if path.starts_with("/admin/buckets/") => {
                let bucket_path = path.strip_prefix("/admin/buckets/").unwrap_or("");
                self.handle_bucket_detail(session.clone(), bucket_path)
                    .await
            }
            ("GET", path) if path.starts_with("/admin/static/") => {
                self.handle_static_file(path).await
            }
            _ => self.not_found().await,
        };

        match result {
            Ok(resp) => Ok(resp),
            Err(e) => Ok(self.error_response(&e)),
        }
    }

    /// GET / - Redirect to profile page
    async fn handle_root(&self) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        Response::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header("Location", "/admin/profile")
            .body(Full::new(Bytes::new()))
            .map_err(CrabCakesError::from)
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
        let params: std::collections::HashMap<String, String> =
            form_urlencoded::parse(query.as_bytes())
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
            .map_err(|e| {
                CrabCakesError::other(&format!("Failed to store user_email in session: {}", e))
            })?;
        session
            .insert("user_id", user_id.clone())
            .await
            .map_err(|e| {
                CrabCakesError::other(&format!("Failed to store user_id in session: {}", e))
            })?;
        session
            .insert("access_key_id", access_key_id.clone())
            .await
            .map_err(|e| {
                CrabCakesError::other(&format!("Failed to store access_key_id in session: {}", e))
            })?;

        // Save the session to persist changes and generate session ID
        session
            .save()
            .await
            .map_err(|e| CrabCakesError::other(&format!("Failed to save session: {}", e)))?;

        // Get session ID - should now be available after save()
        let session_id = session
            .id()
            .map(|id| id.to_string())
            .ok_or_else(|| CrabCakesError::other(&"Failed to get session ID".to_string()))?;

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
    async fn handle_logout(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
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

    /// Helper: Check if user is authenticated
    async fn check_auth(&self, session: &Session) -> Result<(String, String), CrabCakesError> {
        let user_id: Option<String> = session.get("user_id").await.map_err(|e| {
            CrabCakesError::other(&format!("Failed to get user_id from session: {}", e))
        })?;

        if user_id.is_none() {
            return Err(CrabCakesError::other(&"Not authenticated"));
        }

        let user_id = user_id.ok_or_else(|| CrabCakesError::other(&"User ID not found"))?;
        let user_email: String = session
            .get("user_email")
            .await
            .map_err(|e| {
                CrabCakesError::other(&format!("Failed to get user_email from session: {}", e))
            })?
            .ok_or_else(|| CrabCakesError::other(&"User email not found"))?;

        Ok((user_id, user_email))
    }

    /// Helper: Generate CSRF token and store in session
    async fn generate_csrf_token(&self, session: &Session) -> Result<String, CrabCakesError> {
        use rand::Rng;

        // Generate a random 32-byte token
        let token: String = rand::rng()
            .sample_iter(rand::distr::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        // Store in session
        session
            .insert("csrf_token", token.clone())
            .await
            .map_err(|e| CrabCakesError::other(&format!("Failed to store CSRF token: {}", e)))?;

        Ok(token)
    }

    /// Helper: Validate CSRF token from request header
    #[allow(dead_code)]
    async fn validate_csrf_token(
        &self,
        session: &Session,
        req: &Request<hyper::body::Incoming>,
    ) -> Result<(), CrabCakesError> {
        // Get token from X-CSRF-Token header
        let header_token = req
            .headers()
            .get("X-CSRF-Token")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| CrabCakesError::other(&"Missing CSRF token"))?;

        // Get token from session
        let session_token: Option<String> = session
            .get("csrf_token")
            .await
            .map_err(|e| CrabCakesError::other(&format!("Failed to get CSRF token: {}", e)))?;

        let session_token =
            session_token.ok_or_else(|| CrabCakesError::other(&"No CSRF token in session"))?;

        // Compare tokens
        if header_token != session_token {
            return Err(CrabCakesError::other(&"Invalid CSRF token"));
        }

        Ok(())
    }

    /// Helper: Build HTML response with security headers including CSP
    fn build_html_response(&self, html: String) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:;"
            )
            .header("X-Content-Type-Options", "nosniff")
            .header("X-Frame-Options", "DENY")
            .header("Referrer-Policy", "strict-origin-when-cross-origin")
            .body(Full::new(Bytes::from(html)))
            .map_err(CrabCakesError::from)
    }

    /// GET /admin/profile - User profile page
    async fn handle_profile(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        let (user_id, user_email) = match self.check_auth(&session).await {
            Ok(auth) => auth,
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::FOUND)
                    .header("Location", "/login")
                    .body(Full::new(Bytes::new()))
                    .map_err(CrabCakesError::from);
            }
        };

        let access_key_id: String = session
            .get("access_key_id")
            .await
            .map_err(|e| {
                CrabCakesError::other(&format!("Failed to get access_key_id from session: {}", e))
            })?
            .ok_or_else(|| {
                CrabCakesError::other(&"Access key ID not found in session".to_string())
            })?;

        // Get credentials to show expiry
        let creds = self
            .db
            .get_temporary_credentials(&access_key_id)
            .await?
            .ok_or_else(|| {
                CrabCakesError::other(&"Credentials not found or expired".to_string())
            })?;

        // Render template
        let template = ProfileTemplate {
            page: "profile".to_string(),
            user_email,
            user_id,
            access_key_id: creds.access_key_id,
            secret_key_preview: creds.secret_access_key.chars().take(8).collect(),
            expires_at: creds.expires_at.to_string(),
        };

        let html = template
            .render()
            .map_err(|e| CrabCakesError::other(&format!("Failed to render template: {}", e)))?;

        self.build_html_response(html)
    }

    /// GET /admin/policies - List all policies
    async fn handle_policies(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        match self.check_auth(&session).await {
            Ok(_) => {}
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::FOUND)
                    .header("Location", "/login")
                    .body(Full::new(Bytes::new()))
                    .map_err(CrabCakesError::from);
            }
        };

        let policy_names = self.policy_store.get_policy_names();
        let policies: Vec<PolicyInfo> = policy_names
            .iter()
            .filter_map(|name| {
                self.policy_store.get_policy(name).map(|policy| PolicyInfo {
                    name: name.clone(),
                    statement_count: policy.statement.len(),
                })
            })
            .collect();

        let template = PoliciesTemplate {
            page: "policies".to_string(),
            policies,
        };

        let html = template
            .render()
            .map_err(|e| CrabCakesError::other(&format!("Failed to render template: {}", e)))?;

        self.build_html_response(html)
    }

    /// GET /admin/policies/{name} - View policy details
    async fn handle_policy_detail(
        &self,
        session: Session,
        policy_name: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        match self.check_auth(&session).await {
            Ok(_) => {}
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::FOUND)
                    .header("Location", "/login")
                    .body(Full::new(Bytes::new()))
                    .map_err(CrabCakesError::from);
            }
        };

        let policy = self
            .policy_store
            .get_policy(policy_name)
            .ok_or_else(|| CrabCakesError::other(&"Policy not found"))?;

        let policy_json = serde_json::to_string_pretty(&policy)
            .map_err(|e| CrabCakesError::other(&format!("Failed to serialize policy: {}", e)))?;

        let template = PolicyDetailTemplate {
            page: "policies".to_string(),
            policy_name: policy_name.to_string(),
            policy_json,
        };

        let html = template
            .render()
            .map_err(|e| CrabCakesError::other(&format!("Failed to render template: {}", e)))?;

        self.build_html_response(html)
    }

    /// GET /admin/credentials - List all credentials
    async fn handle_credentials(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        match self.check_auth(&session).await {
            Ok(_) => {}
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::FOUND)
                    .header("Location", "/login")
                    .body(Full::new(Bytes::new()))
                    .map_err(CrabCakesError::from);
            }
        };

        let credentials = self.credentials_store.get_access_key_ids();

        let template = CredentialsTemplate {
            page: "credentials".to_string(),
            credentials,
        };

        let html = template
            .render()
            .map_err(|e| CrabCakesError::other(&format!("Failed to render template: {}", e)))?;

        self.build_html_response(html)
    }

    /// GET /admin/buckets - List all buckets
    async fn handle_buckets(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        match self.check_auth(&session).await {
            Ok(_) => {}
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::FOUND)
                    .header("Location", "/login")
                    .body(Full::new(Bytes::new()))
                    .map_err(CrabCakesError::from);
            }
        };

        let buckets = self
            .filesystem
            .list_buckets()
            .map_err(CrabCakesError::from)?;

        let template = BucketsTemplate {
            page: "buckets".to_string(),
            buckets,
        };

        let html = template
            .render()
            .map_err(|e| CrabCakesError::other(&format!("Failed to render template: {}", e)))?;

        self.build_html_response(html)
    }

    /// GET /admin/buckets/{bucket} - View bucket contents
    async fn handle_bucket_detail(
        &self,
        session: Session,
        bucket_path: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        match self.check_auth(&session).await {
            Ok(_) => {}
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::FOUND)
                    .header("Location", "/login")
                    .body(Full::new(Bytes::new()))
                    .map_err(CrabCakesError::from);
            }
        };

        // Extract bucket name from path
        let bucket_name = bucket_path.split('/').next().unwrap_or(bucket_path);

        // List objects in bucket with prefix
        let (entries, _) = self
            .filesystem
            .list_directory(Some(&format!("{}/", bucket_name)), 1000, None)
            .map_err(CrabCakesError::from)?;

        let objects: Vec<ObjectInfo> = entries
            .iter()
            .map(|entry| ObjectInfo {
                key: entry.key.clone(),
                size_formatted: format_size(entry.size),
                last_modified: entry
                    .last_modified
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
            })
            .collect();

        let template = BucketDetailTemplate {
            page: "buckets".to_string(),
            bucket_name: bucket_name.to_string(),
            objects,
        };

        let html = template
            .render()
            .map_err(|e| CrabCakesError::other(&format!("Failed to render template: {}", e)))?;

        self.build_html_response(html)
    }

    /// GET /api/session - Return session info with temp credentials
    async fn handle_get_session(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication using user_id (subject from OIDC claim)
        let user_id: String = session
            .get("user_id")
            .await
            .map_err(|e| {
                CrabCakesError::other(&format!("Failed to get user_id from session: {}", e))
            })?
            .ok_or_else(|| CrabCakesError::other(&"Not authenticated".to_string()))?;

        let user_email: String = session
            .get("user_email")
            .await
            .map_err(|e| {
                CrabCakesError::other(&format!("Failed to get user_email from session: {}", e))
            })?
            .ok_or_else(|| CrabCakesError::other(&"Not authenticated".to_string()))?;

        let access_key_id: String = session
            .get("access_key_id")
            .await
            .map_err(|e| {
                CrabCakesError::other(&format!("Failed to get access_key_id from session: {}", e))
            })?
            .ok_or_else(|| CrabCakesError::other(&"Not authenticated".to_string()))?;

        // Look up credentials in database to get secret key and expiry
        let creds = self
            .db
            .get_temporary_credentials(&access_key_id)
            .await?
            .ok_or_else(|| {
                CrabCakesError::other(&"Credentials not found or expired".to_string())
            })?;

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

    /// GET /admin/api/csrf-token - Get CSRF token for current session
    async fn handle_csrf_token(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Generate or retrieve CSRF token
        let token = self.generate_csrf_token(&session).await?;

        // Return JSON response
        let json = serde_json::to_string(&serde_json::json!({
            "csrf_token": token
        }))?;

        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(json)))
            .map_err(CrabCakesError::from)
    }

    /// Serve static files (CSS, JS)
    async fn handle_static_file(
        &self,
        path: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        use std::path::PathBuf;
        use tokio::fs;

        // Strip /admin/static/ prefix
        let file_path = path.strip_prefix("/admin/static/").unwrap_or("");

        // Prevent directory traversal attacks
        if file_path.contains("..") {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from("Forbidden")))
                .map_err(CrabCakesError::from);
        }

        // Build absolute path to static file
        let static_dir = PathBuf::from("static");
        let absolute_path = static_dir.join(file_path);

        // Read file
        let content = match fs::read(&absolute_path).await {
            Ok(content) => content,
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from("Not Found")))
                    .map_err(CrabCakesError::from);
            }
        };

        // Determine content type
        let content_type = if file_path.ends_with(".js") {
            "application/javascript"
        } else if file_path.ends_with(".css") {
            "text/css"
        } else {
            "application/octet-stream"
        };

        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", content_type)
            .header("Cache-Control", "public, max-age=3600")
            .body(Full::new(Bytes::from(content)))
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
        let error_html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            margin: 0;
            padding: 20px;
        }}
        .error-container {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            padding: 40px;
            max-width: 600px;
            text-align: center;
        }}
        h1 {{
            color: #e53e3e;
            margin: 0 0 20px 0;
        }}
        p {{
            color: #4a5568;
            line-height: 1.6;
            margin: 0 0 30px 0;
        }}
        a {{
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px 24px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 500;
            transition: transform 0.2s;
        }}
        a:hover {{
            transform: translateY(-2px);
        }}
    </style>
</head>
<body>
    <div class="error-container">
        <h1>Error</h1>
        <p>{}</p>
        <a href="/login">Restart Authentication</a>
    </div>
</body>
</html>"#,
            error
        );
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(error_html)))
            .unwrap_or_else(|_| {
                let mut r = Response::new(Full::new(Bytes::from(format!("Error: {}", error))));
                *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                r
            })
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

/// Format file size in human-readable format
fn format_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = size as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", size as u64, UNITS[unit_idx])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}
