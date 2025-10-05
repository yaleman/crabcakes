//! Web UI and API handlers
//!
//! Handles authentication and API endpoints for the admin web interface.

use std::convert::Infallible;
use std::sync::Arc;

use askama::Template;
use form_urlencoded;
use http::header::{
    CACHE_CONTROL, CONTENT_TYPE, LOCATION, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_sessions::Session;

use crate::auth::OAuthClient;
use crate::credentials::CredentialStore;
use crate::db::DBService;
use crate::error::CrabCakesError;
use crate::filesystem::FilesystemService;
use crate::policy::PolicyStore;
use crate::policy_analyzer;

/// Error page template
#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate {
    error_message: String,
}

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
    policy_principal_permissions: Vec<PolicyPrincipalPermission>,
}

/// Principal permission entry for policy detail page (one row per principal+action+resource)
#[derive(Debug, Serialize, PartialEq, Eq, Hash)]
struct PolicyPrincipalPermission {
    arn: String,
    display_name: String,
    identity_type: String,
    effect: String,
    action: String,
    resource: String,
}

/// Policy form template (for creating/editing)
#[derive(Template)]
#[template(path = "policy_form.html")]
struct PolicyFormTemplate {
    page: String,
    policy_name: String,
    policy_json: String,
}

/// Credential form template (for creating/editing)
#[derive(Template)]
#[template(path = "credential_form.html")]
struct CredentialFormTemplate {
    page: String,
    access_key_id: String,
    is_edit: bool,
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

/// Identities list template
#[derive(Template)]
#[template(path = "identities.html")]
struct IdentitiesTemplate {
    page: String,
    identities: Vec<IdentitySummary>,
}

/// Identity detail template
#[derive(Template)]
#[template(path = "identity_detail.html")]
struct IdentityDetailTemplate {
    page: String,
    identity: crate::policy_analyzer::IdentityInfo,
    has_credential: bool,
}

/// Policy info for listing
#[derive(Debug)]
struct PolicyInfo {
    name: String,
    statement_count: usize,
}

/// Identity summary for listing
#[derive(Debug)]
struct IdentitySummary {
    principal_arn: String,
    display_name: String,
    identity_type: String,
    policy_count: usize,
    action_count: usize,
    has_credential: bool,
}

/// Object info for bucket listing
#[derive(Debug)]
struct ObjectInfo {
    key: String,
    size_formatted: String,
    last_modified: String,
}

fn login_redirect() -> Result<Response<Full<Bytes>>, CrabCakesError> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(LOCATION, "/login")
        .body(Full::new(Bytes::new()))
        .map_err(CrabCakesError::from)
}

/// Return with a 404 Not Found response
fn respond_404() -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from("Not Found")));
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

/// Web handler for admin UI and API endpoints
pub struct WebHandler {
    oauth_client: Arc<OAuthClient>,
    db: Arc<DBService>,
    credentials_store: Arc<RwLock<CredentialStore>>,
    policy_store: Arc<PolicyStore>,
    filesystem: Arc<RwLock<FilesystemService>>,
}

impl WebHandler {
    pub fn new(
        oauth_client: Arc<OAuthClient>,
        db: Arc<DBService>,
        credentials_store: Arc<RwLock<CredentialStore>>,
        policy_store: Arc<PolicyStore>,
        filesystem: Arc<RwLock<FilesystemService>>,
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
        let path = req.uri().path().to_string();

        let result = match (method.as_str(), path.as_str()) {
            ("GET", "/") => self.handle_root().await,
            ("GET", "/login") => self.handle_login().await,
            ("GET", path) if path.starts_with("/oauth2/callback") => {
                self.handle_oauth_callback(req, session.clone()).await
            }
            ("POST", "/logout") => self.handle_logout(session.clone()).await,
            ("GET", "/api/session") => self.handle_get_session(session.clone()).await,
            ("GET", "/admin/api/csrf-token") => self.handle_csrf_token(session.clone()).await,
            ("GET", "/admin/api/policies") => self.handle_api_list_policies(session.clone()).await,
            ("POST", "/admin/api/policies") => {
                self.handle_api_create_policy(req, session.clone()).await
            }
            ("PUT", path) if path.starts_with("/admin/api/policies/") => {
                self.handle_api_update_policy(
                    req,
                    session.clone(),
                    path.strip_prefix("/admin/api/policies/").unwrap_or(""),
                )
                .await
            }
            ("DELETE", path) if path.starts_with("/admin/api/policies/") => {
                self.handle_api_delete_policy(
                    req,
                    session.clone(),
                    path.strip_prefix("/admin/api/policies/").unwrap_or(""),
                )
                .await
            }
            ("GET", "/admin/api/credentials") => {
                self.handle_api_list_credentials(session.clone()).await
            }
            ("POST", "/admin/api/credentials") => {
                self.handle_api_create_credential(req, session.clone())
                    .await
            }
            ("PUT", path) if path.starts_with("/admin/api/credentials/") => {
                self.handle_api_update_credential(
                    req,
                    session.clone(),
                    path.strip_prefix("/admin/api/credentials/").unwrap_or(""),
                )
                .await
            }
            ("DELETE", path) if path.starts_with("/admin/api/credentials/") => {
                let access_key_id = path.strip_prefix("/admin/api/credentials/").unwrap_or("");

                if access_key_id.is_empty() {
                    return Ok(respond_404());
                }
                self.handle_api_delete_credential(req, session.clone(), access_key_id)
                    .await
            }
            ("GET", "/admin") | ("GET", "/admin/") => self.handle_root().await,
            ("GET", "/admin/profile") => self.handle_profile(session.clone()).await,
            ("GET", "/admin/policies") => self.handle_policies(session.clone()).await,
            ("GET", "/admin/policies/new") => self.handle_policy_new_form(session.clone()).await,
            ("GET", path) if path.starts_with("/admin/policies/") && path.ends_with("/edit") => {
                let policy_name = path
                    .strip_prefix("/admin/policies/")
                    .and_then(|s| s.strip_suffix("/edit"))
                    .unwrap_or("");
                self.handle_policy_edit_form(session.clone(), policy_name)
                    .await
            }
            ("GET", path) if path.starts_with("/admin/policies/") => {
                let policy_name = path.strip_prefix("/admin/policies/").unwrap_or("");
                self.handle_policy_detail(session.clone(), policy_name)
                    .await
            }
            ("GET", "/admin/identities") => self.handle_identities(session.clone()).await,
            ("GET", "/admin/identities/new") => {
                self.handle_credential_new_form(session.clone()).await
            }
            ("GET", path) if path.starts_with("/admin/identities/") && path.ends_with("/edit") => {
                let access_key_id = path
                    .strip_prefix("/admin/identities/")
                    .and_then(|s| s.strip_suffix("/edit"))
                    .unwrap_or("");

                if access_key_id.is_empty() {
                    return Ok(respond_404());
                }
                self.handle_credential_edit_form(session.clone(), access_key_id)
                    .await
            }
            ("GET", path) if path.starts_with("/admin/identities/") => {
                let access_key_id = path.strip_prefix("/admin/identities/").unwrap_or("");
                if access_key_id.is_empty() {
                    return Ok(respond_404());
                }
                self.handle_identity_detail(session.clone(), access_key_id)
                    .await
            }
            ("GET", "/admin/buckets") => self.handle_buckets(session.clone()).await,
            ("GET", path) if path.starts_with("/admin/buckets/") => {
                let bucket_path = path.strip_prefix("/admin/buckets/").unwrap_or("");
                self.handle_bucket_detail(session.clone(), bucket_path)
                    .await
            }
            ("GET", path) if path.starts_with("/admin/static/") => {
                self.handle_static_file(path).await
            }
            _ => Ok(respond_404()),
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
            .header(LOCATION, "/admin/profile")
            .body(Full::new(Bytes::new()))
            .map_err(CrabCakesError::from)
    }

    /// GET /login - Redirect to OIDC provider
    async fn handle_login(&self) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        let (auth_url, _state) = self.oauth_client.generate_auth_url().await?;

        Response::builder()
            .status(StatusCode::FOUND)
            .header(LOCATION, auth_url)
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
            .header(LOCATION, "/admin/")
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
        login_redirect()
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
        headers: &http::HeaderMap,
    ) -> Result<(), CrabCakesError> {
        // Get token from X-CSRF-Token header
        let header_token = headers
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
            .header(CONTENT_TYPE, "text/html; charset=utf-8")
            .header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:;"
            )
            .header(X_CONTENT_TYPE_OPTIONS, "nosniff")
            .header(X_FRAME_OPTIONS, "DENY")
            .header(REFERRER_POLICY, "strict-origin-when-cross-origin")
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
            Err(_) => return login_redirect(),
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
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };
        let policy_names = self.policy_store.get_policy_names().await;
        let mut policies: Vec<PolicyInfo> = Vec::new();
        for name in policy_names.iter() {
            if let Some(policy) = self.policy_store.get_policy(name).await {
                policies.push(PolicyInfo {
                    name: name.clone(),
                    statement_count: policy.statement.len(),
                });
            }
        }

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
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };

        let policy = self
            .policy_store
            .get_policy(policy_name)
            .await
            .ok_or_else(|| CrabCakesError::other(&"Policy not found"))?;

        let policy_json = serde_json::to_string_pretty(&policy)
            .map_err(|e| CrabCakesError::other(&format!("Failed to serialize policy: {}", e)))?;

        // Extract principal + action + resource combinations from this policy
        let mut policy_principal_permissions = Vec::new();
        for statement in &policy.statement {
            if let Some(ref principal) = statement.principal {
                let principal_to_arns = |principal: &iam_rs::Principal| -> Vec<String> {
                    use iam_rs::{Principal, PrincipalId};
                    match principal {
                        Principal::Wildcard => vec!["*".to_string()],
                        Principal::Aws(principal_id) => match principal_id {
                            PrincipalId::String(arn) => vec![arn.clone()],
                            PrincipalId::Array(arns) => arns.clone(),
                        },
                        Principal::Service(principal_id) => match principal_id {
                            PrincipalId::String(service) => vec![service.clone()],
                            PrincipalId::Array(services) => services.clone(),
                        },
                        _ => vec![],
                    }
                };

                // Extract actions from statement
                let actions = if let Some(ref action) = statement.action {
                    use iam_rs::IAMAction;
                    match action {
                        IAMAction::Single(s) => vec![s.clone()],
                        IAMAction::Multiple(v) => v.clone(),
                    }
                } else {
                    vec![]
                };

                // Extract resources from statement
                let resources = if let Some(ref resource) = statement.resource {
                    use iam_rs::IAMResource;
                    match resource {
                        IAMResource::Single(s) => vec![s.to_string()],
                        IAMResource::Multiple(v) => v.iter().map(|r| r.to_string()).collect(),
                    }
                } else {
                    vec![]
                };

                let effect = format!("{:?}", statement.effect);

                // Create a row for each principal + action + resource combination
                for arn in principal_to_arns(principal) {
                    let display_name = crate::policy_analyzer::extract_display_name(&arn);
                    let identity_type =
                        format!("{}", crate::policy_analyzer::determine_identity_type(&arn));

                    for action in &actions {
                        for resource in &resources {
                            let permission = PolicyPrincipalPermission {
                                arn: arn.clone(),
                                display_name: display_name.clone(),
                                identity_type: identity_type.clone(),
                                effect: effect.clone(),
                                action: action.clone(),
                                resource: resource.clone(),
                            };
                            if !policy_principal_permissions.contains(&permission) {
                                policy_principal_permissions.push(permission);
                            }
                        }
                    }
                }
            }
        }

        let template = PolicyDetailTemplate {
            page: "policies".to_string(),
            policy_name: policy_name.to_string(),
            policy_json,
            policy_principal_permissions,
        };

        let html = template
            .render()
            .map_err(|e| CrabCakesError::other(&format!("Failed to render template: {}", e)))?;

        self.build_html_response(html)
    }

    /// GET /admin/policies/new - Show form for creating a new policy
    async fn handle_policy_new_form(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };

        let template = PolicyFormTemplate {
            page: "policies".to_string(),
            policy_name: String::new(),
            policy_json: String::new(),
        };

        let html = template
            .render()
            .map_err(|e| CrabCakesError::other(&format!("Failed to render template: {}", e)))?;

        self.build_html_response(html)
    }

    /// GET /admin/policies/{name}/edit - Show form for editing a policy
    async fn handle_policy_edit_form(
        &self,
        session: Session,
        policy_name: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };

        let policy = self
            .policy_store
            .get_policy(policy_name)
            .await
            .ok_or_else(|| CrabCakesError::other(&"Policy not found"))?;

        let policy_json = serde_json::to_string_pretty(&policy)
            .map_err(|e| CrabCakesError::other(&format!("Failed to serialize policy: {}", e)))?;

        let template = PolicyFormTemplate {
            page: "policies".to_string(),
            policy_name: policy_name.to_string(),
            policy_json,
        };

        let html = template
            .render()
            .map_err(|e| CrabCakesError::other(&format!("Failed to render template: {}", e)))?;

        self.build_html_response(html)
    }

    /// GET /admin/identities/new - Show form for creating a new credential
    async fn handle_credential_new_form(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };

        let template = CredentialFormTemplate {
            page: "identities".to_string(),
            access_key_id: String::new(),
            is_edit: false,
        };

        let html = template
            .render()
            .map_err(|e| CrabCakesError::other(&format!("Failed to render template: {}", e)))?;

        self.build_html_response(html)
    }

    /// GET /admin/credentials/{id}/edit - Show form for editing a credential
    async fn handle_credential_edit_form(
        &self,
        session: Session,
        access_key_id: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };

        // Verify credential exists
        if self
            .credentials_store
            .read()
            .await
            .get_credential(access_key_id)
            .await
            .is_none()
        {
            return Ok(respond_404());
        }

        let template = CredentialFormTemplate {
            page: "identities".to_string(),
            access_key_id: access_key_id.to_string(),
            is_edit: true,
        };

        let html = template
            .render()
            .map_err(|e| CrabCakesError::other(&format!("Failed to render template: {}", e)))?;

        self.build_html_response(html)
    }

    /// GET /admin/identities - List all identities (credentials)
    async fn handle_identities(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };

        // Get all credentials
        let credential_store = self.credentials_store.read().await;
        let credentials = credential_store.get_access_key_ids().await;

        // Build identity summaries for each credential
        let mut identities: Vec<IdentitySummary> = Vec::new();

        for access_key_id in credentials {
            // Build ARN for this user
            let arn = format!("arn:aws:iam:::user/{}", access_key_id);
            let identity =
                policy_analyzer::get_identity_permissions(&arn, self.policy_store.policies.clone())
                    .await;

            // Check if credential exists
            let has_credential = credential_store
                .get_credential(&access_key_id)
                .await
                .is_some();

            identities.push(IdentitySummary {
                principal_arn: access_key_id.clone(), // Use access_key_id instead of full ARN
                display_name: access_key_id.clone(),
                identity_type: "User".to_string(),
                policy_count: identity.policies.len(),
                action_count: identity.action_count(),
                has_credential,
            });
        }

        let template = IdentitiesTemplate {
            page: "identities".to_string(),
            identities,
        };

        let html = template
            .render()
            .map_err(|e| CrabCakesError::other(&format!("Failed to render template: {}", e)))?;

        self.build_html_response(html)
    }

    /// GET /admin/identities/{access_key_id} - View identity details
    async fn handle_identity_detail(
        &self,
        session: Session,
        access_key_id: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };

        // Build ARN from access_key_id
        let principal_arn = format!("arn:aws:iam:::user/{}", access_key_id);

        let identity = policy_analyzer::get_identity_permissions(
            &principal_arn,
            self.policy_store.policies.clone(),
        )
        .await;

        // Check if credential exists
        let has_credential = self
            .credentials_store
            .read()
            .await
            .get_credential(access_key_id)
            .await
            .is_some();

        let template = IdentityDetailTemplate {
            page: "identities".to_string(),
            identity,
            has_credential,
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
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };

        let buckets = self
            .filesystem
            .read()
            .await
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
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };

        // Extract bucket name from path
        let bucket_name = bucket_path.split('/').next().unwrap_or(bucket_path);

        // List objects in bucket with prefix
        let (entries, _) = self
            .filesystem
            .read()
            .await
            .list_directory(Some(&format!("{}/", bucket_name)), 1000, None)
            .map_err(CrabCakesError::from)?;

        let objects: Vec<ObjectInfo> = entries
            .iter()
            .map(|entry| {
                // Strip bucket name from key for S3 operations
                let key = entry
                    .key
                    .strip_prefix(&format!("{}/", bucket_name))
                    .unwrap_or(&entry.key)
                    .to_string();
                ObjectInfo {
                    key,
                    size_formatted: format_size(entry.size),
                    last_modified: entry
                        .last_modified
                        .format("%Y-%m-%d %H:%M:%S UTC")
                        .to_string(),
                }
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
            .header(CONTENT_TYPE, "application/json")
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
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
            .map_err(CrabCakesError::from)
    }

    /// GET /admin/api/policies - List all policies (JSON)
    async fn handle_api_list_policies(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Get all policy names
        let policy_names = self.policy_store.get_policy_names().await;

        // Build response with policy names and statement counts
        let mut policies = Vec::new();
        for name in policy_names {
            if let Some(policy) = self.policy_store.get_policy(&name).await {
                policies.push(serde_json::json!({
                    "name": name,
                    "statement_count": policy.statement.len()
                }));
            }
        }

        let json = serde_json::to_string(&policies)?;

        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
            .map_err(CrabCakesError::from)
    }

    /// POST /admin/api/policies - Create a new policy
    async fn handle_api_create_policy(
        &self,
        req: Request<hyper::body::Incoming>,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Split request into parts and body
        let (parts, body) = req.into_parts();

        // Validate CSRF token
        self.validate_csrf_token(&session, &parts.headers).await?;

        // Read request body
        let body_bytes = body.collect().await?.to_bytes();
        let body_str = std::str::from_utf8(&body_bytes)
            .map_err(|e| CrabCakesError::other(&format!("Invalid UTF-8: {}", e)))?;

        // Parse request body
        #[derive(serde::Deserialize)]
        struct CreatePolicyRequest {
            name: String,
            policy: iam_rs::IAMPolicy,
        }

        let request: CreatePolicyRequest = serde_json::from_str(body_str)
            .map_err(|e| CrabCakesError::other(&format!("Invalid JSON: {}", e)))?;

        // Add policy
        self.policy_store
            .add_policy(request.name.clone(), request.policy)
            .await?;

        // Return success
        let json = serde_json::to_string(&serde_json::json!({
            "success": true,
            "name": request.name
        }))?;

        Response::builder()
            .status(StatusCode::CREATED)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
            .map_err(CrabCakesError::from)
    }

    /// PUT /admin/api/policies/{name} - Update an existing policy
    async fn handle_api_update_policy(
        &self,
        req: Request<hyper::body::Incoming>,
        session: Session,
        policy_name: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Split request into parts and body
        let (parts, body) = req.into_parts();

        // Validate CSRF token
        self.validate_csrf_token(&session, &parts.headers).await?;

        // Read request body
        let body_bytes = body.collect().await?.to_bytes();
        let body_str = std::str::from_utf8(&body_bytes)
            .map_err(|e| CrabCakesError::other(&format!("Invalid UTF-8: {}", e)))?;

        // Parse policy from request body
        let policy: iam_rs::IAMPolicy = serde_json::from_str(body_str)
            .map_err(|e| CrabCakesError::other(&format!("Invalid JSON: {}", e)))?;

        // Update policy
        self.policy_store
            .update_policy(policy_name.to_string(), policy)
            .await?;

        // Return success
        let json = serde_json::to_string(&serde_json::json!({
            "success": true,
            "name": policy_name
        }))?;

        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
            .map_err(CrabCakesError::from)
    }

    /// DELETE /admin/api/policies/{name} - Delete a policy
    async fn handle_api_delete_policy(
        &self,
        req: Request<hyper::body::Incoming>,
        session: Session,
        policy_name: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Split request into parts for CSRF validation
        let (parts, _body) = req.into_parts();

        // Validate CSRF token
        self.validate_csrf_token(&session, &parts.headers).await?;

        // Delete policy
        self.policy_store.delete_policy(policy_name).await?;

        // Return success
        let json = serde_json::to_string(&serde_json::json!({
            "success": true,
            "name": policy_name
        }))?;

        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
            .map_err(CrabCakesError::from)
    }

    /// GET /admin/api/credentials - List all credentials (JSON)
    async fn handle_api_list_credentials(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Get all access key IDs (NOT secret keys)
        let access_key_ids = self
            .credentials_store
            .read()
            .await
            .get_access_key_ids()
            .await;

        // Build response with just access key IDs
        let credentials: Vec<serde_json::Value> = access_key_ids
            .into_iter()
            .map(|id| {
                serde_json::json!({
                    "access_key_id": id
                })
            })
            .collect();

        let json = serde_json::to_string(&credentials)?;

        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
            .map_err(CrabCakesError::from)
    }

    /// POST /admin/api/credentials - Create a new credential
    async fn handle_api_create_credential(
        &self,
        req: Request<hyper::body::Incoming>,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Split request into parts and body
        let (parts, body) = req.into_parts();

        // Validate CSRF token
        self.validate_csrf_token(&session, &parts.headers).await?;

        // Read request body
        let body_bytes = body.collect().await?.to_bytes();
        let body_str = std::str::from_utf8(&body_bytes)
            .map_err(|e| CrabCakesError::other(&format!("Invalid UTF-8: {}", e)))?;

        // Parse request body
        #[derive(serde::Deserialize)]
        struct CreateCredentialRequest {
            access_key_id: String,
            secret_access_key: String,
        }

        let request: CreateCredentialRequest = serde_json::from_str(body_str)
            .map_err(|e| CrabCakesError::other(&format!("Invalid JSON: {}", e)))?;

        // Add credential
        self.credentials_store
            .write()
            .await
            .add_credential(request.access_key_id.clone(), request.secret_access_key)
            .await?;

        // Return success
        let json = serde_json::to_string(&serde_json::json!({
            "success": true,
            "access_key_id": request.access_key_id
        }))?;

        Response::builder()
            .status(StatusCode::CREATED)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
            .map_err(CrabCakesError::from)
    }

    /// PUT /admin/api/credentials/{access_key_id} - Update an existing credential
    async fn handle_api_update_credential(
        &self,
        req: Request<hyper::body::Incoming>,
        session: Session,
        access_key_id: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Split request into parts and body
        let (parts, body) = req.into_parts();

        // Validate CSRF token
        self.validate_csrf_token(&session, &parts.headers).await?;

        // Read request body
        let body_bytes = body.collect().await?.to_bytes();
        let body_str = std::str::from_utf8(&body_bytes)
            .map_err(|e| CrabCakesError::other(&format!("Invalid UTF-8: {}", e)))?;

        // Parse secret key from request body
        #[derive(serde::Deserialize)]
        struct UpdateCredentialRequest {
            secret_access_key: String,
        }

        let request: UpdateCredentialRequest = serde_json::from_str(body_str)
            .map_err(|e| CrabCakesError::other(&format!("Invalid JSON: {}", e)))?;

        // Update credential
        self.credentials_store
            .write()
            .await
            .update_credential(access_key_id.to_string(), request.secret_access_key)
            .await?;

        // Return success
        let json = serde_json::to_string(&serde_json::json!({
            "success": true,
            "access_key_id": access_key_id
        }))?;

        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
            .map_err(CrabCakesError::from)
    }

    /// DELETE /admin/api/credentials/{access_key_id} - Delete a credential
    async fn handle_api_delete_credential(
        &self,
        req: Request<hyper::body::Incoming>,
        session: Session,
        access_key_id: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Split request into parts for CSRF validation
        let (parts, _body) = req.into_parts();

        // Validate CSRF token
        self.validate_csrf_token(&session, &parts.headers).await?;

        // Delete credential
        self.credentials_store
            .write()
            .await
            .delete_credential(access_key_id)
            .await?;

        // Return success
        let json = serde_json::to_string(&serde_json::json!({
            "success": true,
            "access_key_id": access_key_id
        }))?;

        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
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
            Err(_) => return Ok(respond_404()),
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
            .header(CONTENT_TYPE, content_type)
            .header(CACHE_CONTROL, "public, max-age=3600")
            .body(Full::new(Bytes::from(content)))
            .map_err(CrabCakesError::from)
    }

    /// Error response
    fn error_response(&self, error: &CrabCakesError) -> Response<Full<Bytes>> {
        let template = ErrorTemplate {
            error_message: error.to_string(),
        };

        let html = template.render().unwrap_or_else(|_| {
            format!(
                r#"<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
    <h1>Error</h1>
    <p>{}</p>
    <a href="/login">Restart Authentication</a>
</body>
</html>"#,
                error
            )
        });

        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(html)))
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
