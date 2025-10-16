//! Web UI and API handlers
//!
//! Handles authentication and API endpoints for the admin web interface.

use std::convert::Infallible;
use std::str::FromStr;
use std::sync::Arc;

use askama::Template;
use form_urlencoded;
use http::{
    HeaderValue, Method,
    header::{
        CACHE_CONTROL, CONTENT_TYPE, LOCATION, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
        X_FRAME_OPTIONS,
    },
};
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_sessions::Session;
use tracing::{debug, instrument};

use crate::policy::PolicyStore;
use crate::policy_analyzer;
use crate::{auth::OAuthClient, db::entities::temporary_credentials};
use crate::{constants::TRACE_STATUS_CODE, filesystem::FilesystemService};
use crate::{
    constants::{CSRF_TOKEN_LENGTH, SessionKey, WebPage},
    web::serde::PolicyInfo,
};
use crate::{credentials::CredentialStore, generate_temp_credentials};
use crate::{db::DBService, web::serde::PolicyPrincipalPermission};
use crate::{error::CrabCakesError, request_handler::RequestHandler};

use super::serde::*;
use super::templates::*;

fn login_redirect() -> Result<Response<Full<Bytes>>, CrabCakesError> {
    let mut res = Response::new(Full::new(Bytes::new()));
    res.headers_mut()
        .insert(LOCATION, HeaderValue::from_static("/login"));
    *res.status_mut() = StatusCode::FOUND;
    Ok(res)
}

/// Return with a 404 Not Found response
pub(crate) fn respond_404() -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from("Not Found")));
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

/// Return with a 500 response
pub(crate) fn respond_500(msg: &impl ToString) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(msg.to_string())));
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

/// Web handler for admin UI and API endpoints
pub struct WebHandler {
    oauth_client: Arc<OAuthClient>,
    db: Arc<DBService>,
    credentials_store: Arc<CredentialStore>,
    policy_store: Arc<PolicyStore>,
    filesystem: Arc<FilesystemService>,
    // Shared request handler for business logic
    request_handler: Arc<RequestHandler>,
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
            request_handler: Arc::new(RequestHandler::new(
                db.clone(),
                credentials_store.clone(),
                policy_store.clone(),
                filesystem.clone(),
            )),
            oauth_client,
            db,
            credentials_store,
            policy_store,
            filesystem,
        }
    }

    pub async fn handle_api_request(
        &self,
        req: Request<Incoming>,
        path: &str,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        match (req.method().clone(), path) {
            (Method::POST, "/admin/api/buckets") => self.post_api_bucket(req, session).await,
            (Method::DELETE, path) if path.starts_with("/admin/api/buckets/") => {
                let bucket_name = path.strip_prefix("/admin/api/buckets/").unwrap_or("");
                self.delete_api_bucket(req, session, bucket_name).await
            }
            (Method::GET, "/admin/api/session") => self.handle_get_session(session).await,
            (Method::GET, "/admin/api/csrf-token") => self.handle_csrf_token(session).await,
            (Method::GET, "/admin/api/policies") => self.handle_api_list_policies(session).await,
            (Method::POST, "/admin/api/policies") => {
                self.handle_api_create_policy(req, session).await
            }
            (Method::PUT, path) if path.starts_with("/admin/api/policies/") => {
                self.handle_api_update_policy(
                    req,
                    session,
                    path.strip_prefix("/admin/api/policies/").unwrap_or(""),
                )
                .await
            }
            (Method::DELETE, path) if path.starts_with("/admin/api/policies/") => {
                self.handle_api_delete_policy(
                    req,
                    session,
                    path.strip_prefix("/admin/api/policies/").unwrap_or(""),
                )
                .await
            }
            (Method::POST, path)
                if path.split("?").next().unwrap_or("") == "/admin/api/policy_troubleshooter" =>
            {
                self.post_api_policy_troubleshooter(req, session).await
            }
            (Method::GET, "/admin/api/credentials") => self.get_api_credentials(session).await,
            (Method::POST, "/admin/api/credentials") => {
                self.post_api_credential(req, session).await
            }
            (Method::PUT, path) if path.starts_with("/admin/api/credentials/") => {
                self.put_api_credential(
                    req,
                    session,
                    path.strip_prefix("/admin/api/credentials/").unwrap_or(""),
                )
                .await
            }
            (Method::DELETE, path) if path.starts_with("/admin/api/credentials/") => {
                let access_key_id = path.strip_prefix("/admin/api/credentials/").unwrap_or("");

                if access_key_id.is_empty() {
                    return Ok(respond_404());
                }
                self.delete_api_credential(req, session, access_key_id)
                    .await
            }
            (Method::DELETE, path) if path.starts_with("/admin/api/temp_creds/") => {
                match path.strip_prefix("/admin/api/temp_creds/") {
                    Some(access_key_id) => {
                        self.delete_api_temp_credential(req, session, access_key_id)
                            .await
                    }
                    None => Ok(respond_404()),
                }
            }
            (Method::GET, "/admin/api/database/vacuum") => {
                self.get_api_database_vacuum(session).await
            }
            (Method::POST, "/admin/api/database/vacuum") => {
                self.post_api_database_vacuum(req, session).await
            }
            _ => {
                debug!(method=req.method().as_ref(), path=?path, "API 404 not found ");

                Ok(respond_404())
            }
        }
    }

    /// Main request handler - routes to appropriate endpoint
    #[instrument(
        level = "info",
        skip_all,
        fields(method, uri, remote_addr, status_code, user, bucket, key)
    )]
    pub async fn handle_request(
        &self,
        req: Request<Incoming>,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let is_api_request = path.starts_with("/admin/api/");
        let result = if is_api_request {
            self.handle_api_request(req, &path, session).await
        } else {
            match (method.clone(), path.as_str()) {
                (Method::GET, "/") => self.get_admin().await,
                (Method::GET, "/login") => self.handle_login().await,
                (Method::GET, path) if path.starts_with("/oauth2/callback") => {
                    self.handle_oauth_callback(req, session).await
                }
                (Method::POST, "/logout") => self.handle_logout(session).await,

                (Method::GET, "/admin") | (Method::GET, "/admin/") => self.get_admin().await,
                (Method::GET, "/admin/profile") => self.get_profile(session).await,
                (Method::GET, "/admin/system") => self.get_system(session).await,
                (Method::GET, "/admin/policies") => self.get_policies(session).await,
                (Method::GET, "/admin/policies/new") => self.get_policy_new_form(session).await,
                (Method::GET, "/admin/policy_troubleshooter") => {
                    self.get_policy_troubleshooter(req, session).await
                }
                (Method::GET, path)
                    if path.starts_with("/admin/policies/") && path.ends_with("/edit") =>
                {
                    let policy_name = path
                        .strip_prefix("/admin/policies/")
                        .and_then(|s| s.strip_suffix("/edit"))
                        .unwrap_or("");
                    self.get_policy_edit(session, policy_name).await
                }
                (Method::GET, path) if path.starts_with("/admin/policies/") => {
                    let policy_name = path.strip_prefix("/admin/policies/").unwrap_or("");
                    self.get_policy_detail(session, policy_name).await
                }
                (Method::GET, "/admin/identities") => {
                    self.get_identities(
                        session,
                        form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
                            .filter_map(|(k, v)| {
                                ["order_by", "direction"]
                                    .contains(&k.as_ref())
                                    .then_some((k.to_string(), v.to_string()))
                            })
                            .collect(),
                    )
                    .await
                }
                (Method::GET, "/admin/identities/new") => {
                    let access_key_id = req
                        .uri()
                        .query()
                        .filter(|query| query.contains("access_key_id"))
                        .and_then(|query| {
                            form_urlencoded::parse(query.as_bytes())
                                .into_owned()
                                .find(|(k, _)| k == "access_key_id")
                                .map(|(_, v)| v)
                        })
                        .unwrap_or_default();
                    self.get_identities_new(session, &access_key_id).await
                }
                (Method::GET, path)
                    if path.starts_with("/admin/identities/") && path.ends_with("/edit") =>
                {
                    let access_key_id = path
                        .strip_prefix("/admin/identities/")
                        .and_then(|s| s.strip_suffix("/edit"))
                        .unwrap_or("");

                    if access_key_id.is_empty() {
                        return Ok(respond_404());
                    }
                    self.get_identities_edit(session, access_key_id).await
                }
                (Method::GET, path) if path.starts_with("/admin/identities/") => {
                    let access_key_id = path.strip_prefix("/admin/identities/").unwrap_or("");
                    if access_key_id.is_empty() {
                        return Ok(respond_404());
                    }
                    self.get_identity_detail(session, access_key_id).await
                }
                (Method::GET, "/admin/buckets") => self.get_admin_buckets(session).await,
                (Method::GET, "/admin/buckets/new") => self.get_admin_buckets_new(session).await,
                (Method::GET, path)
                    if path.starts_with("/admin/buckets/") && path.ends_with("/delete") =>
                {
                    let bucket_name = path
                        .strip_prefix("/admin/buckets/")
                        .and_then(|s| s.strip_suffix("/delete"))
                        .unwrap_or("");
                    self.get_bucket_delete_form(session, bucket_name).await
                }

                (Method::GET, path) if path.starts_with("/admin/buckets/") => {
                    let bucket_path = path.strip_prefix("/admin/buckets/").unwrap_or("");
                    self.get_bucket_detail(session, bucket_path).await
                }
                (Method::GET, path) if path.starts_with("/admin/static/") => {
                    self.get_static_file(path).await
                }
                _ => {
                    debug!(method=method.as_ref(), path=?path, "404 not found");
                    Ok(respond_404())
                }
            }
        };
        let span = tracing::Span::current();

        match result {
            Ok(response) => {
                span.record(TRACE_STATUS_CODE, response.status().as_u16());

                Ok(response)
            }
            Err(e) => {
                span.record(
                    TRACE_STATUS_CODE,
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                );
                if is_api_request {
                    debug!("API request error: {:?}", e);
                    match self.build_json_response(json!({
                        "success": false,
                        "error": e
                    })) {
                        Ok(val) => Ok(val),
                        Err(err) => Ok(respond_500(&format!(
                            "Failed to build error response: {err}"
                        ))),
                    }
                } else {
                    Ok(e.into())
                }
            }
        }
    }

    /// GET / - Redirect to profile page
    async fn get_admin(&self) -> Result<Response<Full<Bytes>>, CrabCakesError> {
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
        req: Request<Incoming>,
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
        let (access_key_id, secret_access_key) = generate_temp_credentials();

        // Set credentials to expire in 8 hours
        let expires_at = chrono::Utc::now()
            + chrono::Duration::try_hours(8).ok_or_else(|| {
                CrabCakesError::other(&"Failed to create credential expiry duration".to_string())
            })?;

        // Store session data
        session
            .insert(SessionKey::UserEmail.as_ref(), user_email.clone())
            .await
            .map_err(|e| {
                CrabCakesError::other(&format!("Failed to store user_email in session: {}", e))
            })?;
        session
            .insert(SessionKey::UserId.as_ref(), user_id.clone())
            .await
            .map_err(|e| {
                CrabCakesError::other(&format!("Failed to store user_id in session: {}", e))
            })?;
        session
            .insert(SessionKey::AccessKeyId.as_ref(), access_key_id.clone())
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
        let user_id: Option<String> =
            session
                .get(SessionKey::UserId.as_ref())
                .await
                .map_err(|e| {
                    CrabCakesError::other(&format!("Failed to get user_id from session: {}", e))
                })?;

        if user_id.is_none() {
            return Err(CrabCakesError::other(&"Not authenticated"));
        }

        let user_id = user_id.ok_or_else(|| CrabCakesError::other(&"User ID not found"))?;
        let user_email: String = session
            .get(SessionKey::UserEmail.as_ref())
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

        // Generate a random [CSRF_TOKEN_LENGTH]-byte token
        let token: String = rand::rng()
            .sample_iter(rand::distr::Alphanumeric)
            .take(CSRF_TOKEN_LENGTH)
            .map(char::from)
            .collect();

        // Store in session
        session
            .insert(SessionKey::CsrfToken.as_ref(), token.clone())
            .await
            .map_err(|e| CrabCakesError::other(&format!("Failed to store CSRF token: {}", e)))?;

        Ok(token)
    }

    /// Helper: Validate CSRF token from request header
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
            .get(SessionKey::CsrfToken.as_ref())
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
    fn build_html_response(
        &self,
        html: impl Template,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
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
            .body(Full::new(Bytes::from(html.render()?)))
            .map_err(CrabCakesError::from)
    }

    fn build_json_response(
        &self,
        json: impl Serialize,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        let body = serde_json::to_string(&json).inspect_err(|err| {
            debug!("Failed to serialize JSON response: {err:?}");
        })?;

        let mut res = Response::new(Full::new(Bytes::from(body)));

        *res.status_mut() = StatusCode::OK;

        res.headers_mut().extend(vec![
            (CONTENT_TYPE, HeaderValue::from_static("application/json")),
            (CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
            (X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
            (
                REFERRER_POLICY,
                HeaderValue::from_static("strict-origin-when-cross-origin"),
            ),
        ]);

        Ok(res)
    }

    /// GET /admin/profile - User profile page
    async fn get_profile(&self, session: Session) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        let (user_id, user_email) = match self.check_auth(&session).await {
            Ok(auth) => auth,
            Err(_) => return login_redirect(),
        };

        let access_key_id: String = session
            .get(SessionKey::AccessKeyId.as_ref())
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
            page: WebPage::Profile.as_ref(),
            user_email,
            user_id,
            access_key_id: creds.access_key_id,
            secret_key_preview: creds.secret_access_key.chars().take(8).collect(),
            expires_at: creds.expires_at.to_string(),
        };

        self.build_html_response(template)
    }

    /// GET /admin/system - System information page
    async fn get_system(&self, session: Session) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        }

        let template = SystemTemplate {
            page: WebPage::System.as_ref(),
        };

        self.build_html_response(template)
    }

    /// GET /admin/policies - List all policies
    async fn get_policies(
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
            page: WebPage::Policies.as_ref(),
            policies,
        };

        self.build_html_response(template)
    }

    /// GET /admin/policies/{name} - View policy details
    async fn get_policy_detail(
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
            page: WebPage::Policies.as_ref(),
            policy_name: policy_name.to_string(),
            policy_json,
            policy_principal_permissions,
        };

        self.build_html_response(template)
    }

    /// GET /admin/policies/new - Show form for creating a new policy
    async fn get_policy_new_form(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };

        let template = PolicyFormTemplate {
            page: WebPage::Policies.as_ref(),
            policy_name: String::new(),
            policy_json: String::new(),
        };

        self.build_html_response(template)
    }

    /// GET /admin/policies/{name}/edit - Show form for editing a policy
    async fn get_policy_edit(
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
            page: WebPage::Policies.as_ref(),
            policy_name: policy_name.to_string(),
            policy_json,
        };

        self.build_html_response(template)
    }

    /// GET /admin/identities/new - Show form for creating a new credential
    async fn get_identities_new(
        &self,
        session: Session,
        access_key_id: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };
        // check if the akid already exists and reject the request if so
        if self
            .credentials_store
            .get_credential(access_key_id)
            .await
            .is_some()
        {
            return Err(CrabCakesError::CredentialAlreadyExists);
        }

        self.build_html_response(CredentialFormTemplate {
            access_key_id: access_key_id.to_string(),
            is_edit: false,
            ..Default::default()
        })
    }

    /// GET /admin/credentials/{id}/edit - Show form for editing a credential
    async fn get_identities_edit(
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
            .get_credential(access_key_id)
            .await
            .is_none()
        {
            return Ok(respond_404());
        }

        let template = CredentialFormTemplate {
            access_key_id: access_key_id.to_string(),
            is_edit: true,
            ..Default::default()
        };

        self.build_html_response(template)
    }

    /// GET /admin/identities - List all identities (credentials)
    async fn get_identities(
        &self,
        session: Session,
        query_params: Vec<(String, String)>,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };

        // Get all credentials
        let credentials = self.credentials_store.get_access_key_ids().await;

        // Build identity summaries for each credential
        let mut identities: Vec<IdentitySummary> = Vec::new();

        for access_key_id in credentials {
            // Build ARN for this user
            let arn = format!("arn:aws:iam:::user/{}", access_key_id);
            let identity =
                policy_analyzer::get_identity_permissions(&arn, self.policy_store.policies.clone())
                    .await;

            // Check if credential exists
            let has_credential = self
                .credentials_store
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

        let order_by = query_params
            .iter()
            .find(|(k, _)| k == "order_by")
            .map(|(_, v)| {
                temporary_credentials::Column::from_str(v.as_ref())
                    .unwrap_or(temporary_credentials::Column::CreatedAt)
            });

        let direction = query_params
            .iter()
            .find(|(k, _)| k == "direction")
            .map(|(_, v)| match v.as_ref() {
                "asc" => sea_orm::Order::Asc,
                "desc" => sea_orm::Order::Desc,
                _ => sea_orm::Order::Desc,
            });

        // Get all temporary credentials
        let temp_creds = self
            .db
            .get_all_temporary_credentials(order_by, direction)
            .await?;
        let temporary_credentials: Vec<TemporaryCredentialSummary> = temp_creds
            .into_iter()
            .map(|cred| TemporaryCredentialSummary {
                access_key_id: cred.access_key_id,
                user_email: cred.user_email,
                user_id: cred.user_id,
                expires_at: cred.expires_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                created_at: cred.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            })
            .collect();

        let template = IdentitiesTemplate {
            page: WebPage::Identities.as_ref(),
            identities,
            temporary_credentials,
        };

        self.build_html_response(template)
    }

    /// GET /admin/identities/{access_key_id} - View identity details
    async fn get_identity_detail(
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
            .get_credential(access_key_id)
            .await
            .is_some();

        let template = IdentityDetailTemplate {
            page: WebPage::Identities.as_ref(),
            identity,
            has_credential,
        };

        self.build_html_response(template)
    }

    /// GET /admin/buckets - List all buckets
    async fn get_admin_buckets(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };

        let buckets = self
            .filesystem
            .list_buckets()
            .await
            .map_err(CrabCakesError::from)?;

        let template = BucketsTemplate {
            buckets,
            ..Default::default()
        };

        self.build_html_response(template)
    }

    /// GET /admin/buckets/{bucket} - View bucket contents
    async fn get_bucket_detail(
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
            .list_directory(Some(&format!("{}/", bucket_name)), 1000, None)
            .await
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
            page: WebPage::Buckets.as_ref(),
            bucket_name: bucket_name.to_string(),
            objects,
        };

        self.build_html_response(template)
    }

    /// GET /admin/buckets/new - Show form for creating a new bucket
    async fn get_admin_buckets_new(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };

        let template = BucketFormTemplate {
            page: WebPage::Buckets.as_ref(),
        };

        self.build_html_response(template)
    }

    /// POST /admin/api/buckets - Create a new bucket
    async fn post_api_bucket(
        &self,
        req: Request<Incoming>,
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
        struct CreateBucketRequest {
            bucket_name: String,
        }

        let request: CreateBucketRequest = serde_json::from_str(body_str)
            .map_err(|e| CrabCakesError::other(&format!("Invalid JSON: {}", e)))?;

        // Call extracted business logic
        self.request_handler
            .api_create_bucket(&request.bucket_name)
            .await?;

        // Return success
        self.build_json_response(json!({
            "success": true,
            "bucket_name": request.bucket_name
        }))
    }

    /// GET /admin/buckets/{name}/delete - Show bucket deletion confirmation page
    async fn get_bucket_delete_form(
        &self,
        session: Session,
        bucket_name: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };

        // Get object count for the bucket
        let (entries, _) = self
            .filesystem
            .list_directory(Some(&format!("{}/", bucket_name)), 10000, None)
            .await
            .map_err(CrabCakesError::from)?;

        let template = BucketDeleteTemplate {
            page: WebPage::Buckets.as_ref(),
            bucket_name: bucket_name.to_string(),
            object_count: entries.len(),
        };

        self.build_html_response(template)
    }

    /// DELETE /admin/api/buckets/{name} - Delete a bucket
    async fn delete_api_bucket(
        &self,
        req: Request<Incoming>,
        session: Session,
        bucket_name: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Split request into parts
        let (parts, _body) = req.into_parts();

        // Validate CSRF token
        self.validate_csrf_token(&session, &parts.headers).await?;

        // Check if force parameter is provided
        let query = parts.uri.query().unwrap_or("");
        let force = query.contains("force=true");

        self.request_handler
            .api_delete_bucket(bucket_name, force)
            .await?;

        // Return success
        self.build_json_response(json!({
            "success": true,
            "bucket_name": bucket_name
        }))
    }

    /// GET /api/session - Return session info with temp credentials
    async fn handle_get_session(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication using user_id (subject from OIDC claim)
        self.check_auth(&session).await?;

        let user_id: String = session
            .get(SessionKey::UserId.as_ref())
            .await
            .map_err(|e| {
                CrabCakesError::other(&format!("Failed to get user_id from session: {}", e))
            })?
            .ok_or_else(|| CrabCakesError::other(&"Not authenticated".to_string()))?;

        let user_email: String = session
            .get(SessionKey::UserEmail.as_ref())
            .await
            .map_err(|e| {
                CrabCakesError::other(&format!("Failed to get user_email from session: {}", e))
            })?
            .ok_or_else(|| CrabCakesError::other(&"Not authenticated".to_string()))?;

        // Save the session to ensure we have a session ID
        session
            .save()
            .await
            .map_err(|e| CrabCakesError::other(&format!("Failed to save session: {}", e)))?;

        // Get session ID
        let session_id = session
            .id()
            .map(|id| id.to_string())
            .ok_or_else(|| CrabCakesError::other(&"Failed to get session ID".to_string()))?;

        // Get or create credentials for this session
        let (creds, was_created) = self
            .db
            .get_or_create_credentials_for_session(
                &session_id,
                &user_email,
                &user_id,
                generate_temp_credentials,
            )
            .await?;

        // If new credentials were created, store the access_key_id in session
        if was_created {
            session
                .insert(
                    SessionKey::AccessKeyId.as_ref(),
                    creds.access_key_id.clone(),
                )
                .await
                .map_err(|e| {
                    CrabCakesError::other(&format!(
                        "Failed to store access_key_id in session: {}",
                        e
                    ))
                })?;
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
        self.build_json_response(&session_info)
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

        #[derive(Serialize)]
        struct CsrfTokenResponse {
            csrf_token: String,
        }

        impl CsrfTokenResponse {
            fn new(csrf_token: String) -> Self {
                Self { csrf_token }
            }
        }

        // Return JSON response
        self.build_json_response(CsrfTokenResponse::new(token))
    }

    /// GET /admin/api/policies - List all policies (JSON)
    async fn handle_api_list_policies(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Call extracted business logic
        let policies = self.request_handler.api_list_policies().await?;

        self.build_json_response(&policies)
    }

    /// POST /admin/api/policies - Create a new policy
    async fn handle_api_create_policy(
        &self,
        req: Request<Incoming>,
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

        // Call extracted business logic
        self.request_handler
            .api_create_policy(&request.name, request.policy)
            .await?;

        // Return success
        self.build_json_response(json!({
            "success": true,
            "name": request.name
        }))
    }

    /// PUT /admin/api/policies/{name} - Update an existing policy
    async fn handle_api_update_policy(
        &self,
        req: Request<Incoming>,
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
        let policy: iam_rs::IAMPolicy = match serde_json::from_str(body_str) {
            Ok(p) => p,
            Err(e) => {
                return self.build_json_response(json!({
                    "success": false,
                    "error": format!("Invalid JSON: {}", e)
                }));
            }
        };

        // Call extracted business logic
        self.request_handler
            .api_update_policy(policy_name.to_string(), policy)
            .await?;

        // Return success
        let json = json!({
            "success": true,
            "name": policy_name
        });

        self.build_json_response(json)
    }

    /// DELETE /admin/api/policies/{name} - Delete a policy
    async fn handle_api_delete_policy(
        &self,
        req: Request<Incoming>,
        session: Session,
        policy_name: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Split request into parts for CSRF validation
        let (parts, _body) = req.into_parts();

        // Validate CSRF token
        self.validate_csrf_token(&session, &parts.headers).await?;

        // Call extracted business logic
        self.request_handler.api_delete_policy(policy_name).await?;

        // Return success
        self.build_json_response(json!({
            "success": true,
            "name": policy_name
        }))
    }

    /// GET /admin/api/credentials - List all credentials (JSON)
    async fn get_api_credentials(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Call extracted business logic
        let credentials = self.request_handler.api_list_credentials().await?;

        self.build_json_response(&credentials)
    }

    /// POST /admin/api/credentials - Create a new credential
    async fn post_api_credential(
        &self,
        req: Request<Incoming>,
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

        // Call extracted business logic
        self.request_handler
            .api_create_credential(request.access_key_id.clone(), request.secret_access_key)
            .await?;

        // Return success
        self.build_json_response(json!({
            "success": true,
            "access_key_id": request.access_key_id
        }))
    }

    /// PUT /admin/api/credentials/{access_key_id} - Update an existing credential
    async fn put_api_credential(
        &self,
        req: Request<Incoming>,
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

        // Call extracted business logic
        self.request_handler
            .api_update_credential(access_key_id.to_string(), request.secret_access_key)
            .await?;

        // Return success
        self.build_json_response(json!({
            "success": true,
            "access_key_id": access_key_id
        }))
    }

    /// DELETE /admin/api/credentials/{access_key_id} - Delete a credential
    async fn delete_api_credential(
        &self,
        req: Request<Incoming>,
        session: Session,
        access_key_id: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Split request into parts for CSRF validation
        let (parts, _body) = req.into_parts();

        // Validate CSRF token
        self.validate_csrf_token(&session, &parts.headers).await?;

        // Call extracted business logic
        self.request_handler
            .api_delete_credential(access_key_id)
            .await?;

        // Return success
        self.build_json_response(json!({
            "success": true,
            "access_key_id": access_key_id
        }))
    }

    /// DELETE /admin/api/temp_creds/{access_key_id} - Delete a temporary credential
    async fn delete_api_temp_credential(
        &self,
        req: Request<Incoming>,
        session: Session,
        access_key_id: &str,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Split request into parts for CSRF validation
        let (parts, _body) = req.into_parts();

        // Validate CSRF token
        self.validate_csrf_token(&session, &parts.headers).await?;

        // Call extracted business logic
        self.request_handler
            .api_delete_temp_credential(access_key_id)
            .await?;

        // Return success
        self.build_json_response(json!({
            "success": true,
            "access_key_id": access_key_id
        }))
    }

    /// Serve static files (CSS, JS)
    async fn get_static_file(&self, path: &str) -> Result<Response<Full<Bytes>>, CrabCakesError> {
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

    async fn get_policy_troubleshooter(
        &self,
        req: Request<Incoming>,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        if self.check_auth(&session).await.is_err() {
            return login_redirect();
        };
        let (parts, _body) = req.into_parts();

        let mut policy_names: Vec<String> = self
            .policy_store
            .policies
            .read()
            .await
            .keys()
            .cloned()
            .collect();
        policy_names.sort();

        let mut template = PolicyTroubleshooterTemplate {
            policy_names,
            ..Default::default()
        };
        if let Some(query) = parts.uri.query() {
            form_urlencoded::parse(query.as_bytes()).for_each(|(key, value)| match key.as_ref() {
                "bucket" => template.bucket = value.to_string(),
                "key" => template.key = value.to_string(),
                "user" => template.user = value.to_string(),
                "action" => template.action = value.to_string(),
                _ => {}
            });
        }

        self.build_html_response(template)
    }

    async fn post_api_policy_troubleshooter(
        &self,
        req: Request<Incoming>,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // parse out the form
        let body = req.into_body();
        let body_bytes = body.collect().await?.to_bytes();
        let body_str = std::str::from_utf8(&body_bytes)
            .map_err(|e| CrabCakesError::other(&format!("Invalid UTF-8: {}", e)))?;

        let form: TroubleShooterForm = serde_json::from_str(body_str)?;

        let response = self.request_handler.api_troubleshooter(form).await?;
        self.build_json_response(response)
    }

    /// GET /admin/api/database/vacuum - Check if database needs vacuuming
    async fn get_api_database_vacuum(
        &self,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Call extracted business logic
        let vacuum_stats = self.request_handler.api_database_vacuum_status().await?;

        // Calculate percentage and needs_vacuum flag
        let percentage = if vacuum_stats.page_count > 0 {
            (vacuum_stats.freelist_count as f64 / vacuum_stats.page_count as f64) * 100.0
        } else {
            0.0
        };
        let needs_vacuum = percentage > 10.0;

        #[derive(Serialize)]
        struct VacuumCheckResponse {
            needs_vacuum: bool,
            freelist_count: i64,
            page_count: i64,
            percentage: f64,
        }

        let response = VacuumCheckResponse {
            needs_vacuum,
            freelist_count: vacuum_stats.freelist_count,
            page_count: vacuum_stats.page_count,
            percentage,
        };

        self.build_json_response(response)
    }

    /// POST /admin/api/database/vacuum - Execute database vacuum
    async fn post_api_database_vacuum(
        &self,
        req: Request<Incoming>,
        session: Session,
    ) -> Result<Response<Full<Bytes>>, CrabCakesError> {
        // Check authentication
        self.check_auth(&session).await?;

        // Split request into parts for CSRF validation
        let (parts, _body) = req.into_parts();

        // Validate CSRF token
        self.validate_csrf_token(&session, &parts.headers).await?;

        // Check if confirm parameter is present
        let query = parts.uri.query().unwrap_or("");
        let confirm = query.contains("confirm=true");

        // Call extracted business logic
        let result = self.request_handler.api_database_vacuum(confirm).await?;

        #[derive(Serialize)]
        struct VacuumExecuteResponse {
            success: bool,
            reclaimed_pages: i64,
        }

        let response = VacuumExecuteResponse {
            success: result.success,
            reclaimed_pages: result.pages_freed,
        };

        self.build_json_response(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iam_rs::Decision;

    /// Helper to build TroubleShooterForm
    fn build_troubleshooter_form(
        bucket: &str,
        key: &str,
        user: &str,
        action: &str,
        policy: &str,
    ) -> TroubleShooterForm {
        TroubleShooterForm {
            bucket: bucket.to_string(),
            key: key.to_string(),
            user: user.to_string(),
            action: action.to_string(),
            policy: policy.to_string(),
        }
    }

    #[tokio::test]
    async fn test_error_response() {
        let response: Response<Full<Bytes>> = CrabCakesError::other(&"Test error").into();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let mut body: Full<Bytes> = response.into_body();
        let body_bytes = body
            .frame()
            .await
            .expect("Couldn't get frame")
            .expect("failed to get frame")
            .into_data()
            .expect("Failed to get bytes from frame");
        let body_str = std::str::from_utf8(&body_bytes).expect("Body is not valid UTF-8");
        assert!(body_str.contains("Test error"));
    }

    // Allow Scenario Tests

    #[tokio::test]
    async fn test_troubleshooter_testuser_bucket1_testuser_prefix_allow() {
        let request_handler = RequestHandler::new_test().await;

        let form = build_troubleshooter_form(
            "bucket1",
            "testuser/file.txt",
            "testuser",
            "s3:GetObject",
            "",
        );

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        assert_eq!(response.decision.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_troubleshooter_testuser_bucket1_testuser_wildcard_allow() {
        let request_handler = RequestHandler::new_test().await;
        let form = build_troubleshooter_form(
            "bucket1",
            "testuser/subdir/file.txt",
            "testuser",
            "s3:PutObject",
            "",
        );

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        assert_eq!(response.decision.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_troubleshooter_testuser_bucket2_allow() {
        let request_handler = RequestHandler::new_test().await;
        let form = build_troubleshooter_form("bucket2", "file.txt", "testuser", "s3:PutObject", "");

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        assert_eq!(response.decision.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_troubleshooter_testuser_bucket2_root_allow() {
        let request_handler = RequestHandler::new_test().await;
        let form = build_troubleshooter_form("bucket2", "", "testuser", "s3:ListBucket", "");

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        assert_eq!(response.decision.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_troubleshooter_testuser_list_all_buckets_allow() {
        let request_handler = RequestHandler::new_test().await;
        let form = build_troubleshooter_form("", "", "testuser", "s3:ListAllMyBuckets", "");

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        assert_eq!(response.decision.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_troubleshooter_testuser_list_bucket1_allow() {
        let request_handler = RequestHandler::new_test().await;
        let form = build_troubleshooter_form("bucket1", "", "testuser", "s3:ListBucket", "");

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        assert_eq!(response.decision.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_troubleshooter_testuser_create_bucket21_allow() {
        let request_handler = RequestHandler::new_test().await;
        let form = build_troubleshooter_form("bucket21", "", "testuser", "s3:CreateBucket", "");

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        assert_eq!(response.decision.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_troubleshooter_testuser_delete_bucket21_allow() {
        let request_handler = RequestHandler::new_test().await;
        let form = build_troubleshooter_form("bucket21", "", "testuser", "s3:DeleteBucket", "");

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        assert_eq!(response.decision.decision, Decision::Allow);
    }

    // Deny Scenario Tests

    #[tokio::test]
    async fn test_troubleshooter_testuser_bucket1_other_prefix_deny() {
        let request_handler = RequestHandler::new_test().await;
        let form =
            build_troubleshooter_form("bucket1", "other/file.txt", "testuser", "s3:GetObject", "");

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        // No matching policy = NotApplicable (implicit deny)
        assert_eq!(response.decision.decision, Decision::NotApplicable);
    }

    #[tokio::test]
    async fn test_troubleshooter_testuser_bucket3_deny() {
        let request_handler = RequestHandler::new_test().await;
        let form = build_troubleshooter_form("bucket3", "file.txt", "testuser", "s3:GetObject", "");

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        // No matching policy = NotApplicable (implicit deny)
        assert_eq!(response.decision.decision, Decision::NotApplicable);
    }

    #[tokio::test]
    async fn test_troubleshooter_testuser_bucket1_root_putobject_deny() {
        let request_handler = RequestHandler::new_test().await;
        let form = build_troubleshooter_form("bucket1", "file.txt", "testuser", "s3:PutObject", "");

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        // No matching policy = NotApplicable (implicit deny)
        assert_eq!(response.decision.decision, Decision::NotApplicable);
    }

    // Different User Tests

    #[tokio::test]
    async fn test_troubleshooter_otheruser_bucket1_deny() {
        let request_handler = RequestHandler::new_test().await;
        let form = build_troubleshooter_form(
            "bucket1",
            "testuser/file.txt",
            "otheruser",
            "s3:GetObject",
            "",
        );

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        // No matching policy = NotApplicable (implicit deny)
        assert_eq!(response.decision.decision, Decision::NotApplicable);
    }

    #[tokio::test]
    async fn test_troubleshooter_otheruser_bucket2_deny() {
        let request_handler = RequestHandler::new_test().await;
        let form =
            build_troubleshooter_form("bucket2", "file.txt", "otheruser", "s3:PutObject", "");

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        // No matching policy = NotApplicable (implicit deny)
        assert_eq!(response.decision.decision, Decision::NotApplicable);
    }

    // Edge Case Tests

    #[tokio::test]
    async fn test_troubleshooter_empty_bucket_becomes_wildcard() {
        let request_handler = RequestHandler::new_test().await;
        let form = build_troubleshooter_form("", "", "testuser", "s3:ListBucket", "");

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        // Empty bucket becomes wildcard, testuser has ListBucket on * via ListAllMyBuckets statement
        // But ListBucket action specifically is NOT allowed on wildcard in the policy
        // No matching policy = NotApplicable (implicit deny)
        assert_eq!(response.decision.decision, Decision::NotApplicable);
    }

    #[tokio::test]
    async fn test_troubleshooter_bucket_level_operation() {
        let request_handler = RequestHandler::new_test().await;
        let form = build_troubleshooter_form("bucket1", "", "testuser", "s3:ListBucket", "");

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        // Bucket-level operation with no key
        assert_eq!(response.decision.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_troubleshooter_specific_policy_filter() {
        let request_handler = RequestHandler::new_test().await;
        let form = build_troubleshooter_form(
            "bucket1",
            "testuser/file.txt",
            "testuser",
            "s3:GetObject",
            "testuser",
        );

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        // Should evaluate only the testuser policy
        assert_eq!(response.decision.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_troubleshooter_all_policies_evaluated() {
        let request_handler = RequestHandler::new_test().await;
        let form = build_troubleshooter_form(
            "bucket1",
            "testuser/file.txt",
            "testuser",
            "s3:GetObject",
            "",
        );

        let response = request_handler
            .api_troubleshooter(form)
            .await
            .expect("Request should succeed");

        // Empty policy name evaluates all policies
        assert_eq!(response.decision.decision, Decision::Allow);
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
