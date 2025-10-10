//! AWS Signature Version 4 authentication and authorization.
//!
//! Provides signature verification for both standard and streaming S3 requests,
//! along with IAM request context building for policy evaluation.

use std::str::FromStr;
use std::sync::Arc;

use chrono::Utc;
use http::request::Parts;
use http::{HeaderValue, Method};
use hyper::body::Bytes;
use hyper::{Request, header::AUTHORIZATION};
use iam_rs::{Arn, Context, ContextValue, IAMRequest, Principal, PrincipalId};
use scratchstack_aws_principal::{self, SessionData};
use scratchstack_aws_signature::auth::SigV4AuthenticatorResponse;
use scratchstack_aws_signature::{
    GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, NO_ADDITIONAL_SIGNED_HEADERS,
    SignatureOptions, service_for_signing_key_fn, sigv4_validate_request,
};
use tokio::sync::RwLock;
use tower::BoxError;
use tracing::{debug, trace};

use crate::constants::{S3, S3Action};
use crate::credentials::CredentialStore;
use crate::db::DBService;
use crate::error::CrabCakesError;

/// Mock AWS Account ID for generated principals
const MOCK_ACCOUNT_ID: &str = "000000000000";

/// Extract authentication context from HTTP request
pub struct AuthContext {
    pub principal: Principal,
    pub username: Option<String>,
}

/// Verification result for AWS SigV4 signature
#[derive(Debug)]
pub struct VerifiedRequest {
    pub access_key_id: String,
    pub principal: scratchstack_aws_principal::Principal,
}

/// Verify AWS Signature V4 for a request
pub async fn verify_sigv4(
    req: http::Request<Vec<u8>>,
    credentials_store: Arc<RwLock<CredentialStore>>,
    db: Arc<DBService>,
    region: &str,
) -> Result<(Parts, Bytes, SigV4AuthenticatorResponse), CrabCakesError> {
    // Check if Authorization header exists
    let auth_header = req.headers().get(AUTHORIZATION);

    if auth_header.is_none() || auth_header == Some(&HeaderValue::from_static("")) {
        return Err(CrabCakesError::NoAuthenticationSupplied(
            "Missing authorization header".to_string(),
        ));
    }

    // Create a closure that will fetch signing keys
    let get_signing_key = {
        let cred_store = credentials_store.clone();
        let db_service = db.clone();
        move |request: GetSigningKeyRequest| {
            let cred_store = cred_store.clone();
            let db_service = db_service.clone();
            async move {
                let access_key = request.access_key().to_string();
                debug!(access_key = %access_key, "Looking up signing key");

                // Try to get the credential from the permanent store first
                let secret_access_key = if let Some(secret) =
                    cred_store.read().await.get_credential(&access_key).await
                {
                    debug!(access_key = %access_key, "Found credential in permanent store");
                    secret
                } else {
                    // Try the database for temporary credentials
                    debug!(access_key = %access_key, "Checking database for temporary credentials");
                    let temp_cred = db_service
                        .get_temporary_credentials(&access_key)
                        .await
                        .map_err(|e| {
                            debug!(access_key = %access_key, error = %e, "Database lookup failed");
                            BoxError::from(format!("Database lookup failed: {}", e))
                        })?
                        .ok_or_else(|| {
                            debug!(access_key = %access_key, "Credential not found in database");
                            BoxError::from("Invalid credential identifier".to_string())
                        })?;

                    // Check if temporary credentials are expired
                    if temp_cred.expires_at < Utc::now() {
                        debug!(access_key = %access_key, "Temporary credentials have expired");
                        return Err(BoxError::from("Temporary credentials expired".to_string()));
                    }

                    debug!(access_key = %access_key, "Found valid temporary credential in database");
                    temp_cred.secret_access_key
                };

                // Convert secret key to KSecretKey
                debug!(access_key = %access_key, secret_key_length = secret_access_key.len(), "About to parse secret key");
                let secret_key = KSecretKey::from_str(&secret_access_key).map_err(|err| {
                    debug!(
                        access_key_id = access_key,
                        "Failed to parse secret key: {}", err
                    );
                    BoxError::from(format!("Failed to parse secret key: {}", err))
                })?;

                // Generate signing key
                let signing_key = secret_key.to_ksigning(
                    request.request_date(),
                    request.region(),
                    request.service(),
                );

                // Create a mock principal (we'll use the access key as username)
                let principal =
                    scratchstack_aws_principal::User::new("aws", MOCK_ACCOUNT_ID, "/", &access_key)
                        .map_err(|e| {
                            BoxError::from(format!("Failed to create principal: {}", e))
                        })?;

                GetSigningKeyResponse::builder()
                    .principal(principal)
                    .signing_key(signing_key)
                    .build()
                    .map_err(|e| {
                        BoxError::from(format!("Failed to build signing key response: {}", e))
                    })
            }
        }
    };

    // Wrap the closure in a tower::Service
    let mut service = service_for_signing_key_fn(get_signing_key);

    // S3-specific signature options
    let signature_options = SignatureOptions::S3;

    trace!("Signature options: {:?}", signature_options);

    // Log request details for debugging
    trace!(
        method = %req.method(),
        uri = %req.uri(),
        headers = ?req.headers(),
        "Validating SigV4 request"
    );

    // Validate the request
    let (parts, body, auth) = sigv4_validate_request(
        req,
        region,
        S3,
        &mut service,
        Utc::now(),
        &NO_ADDITIONAL_SIGNED_HEADERS,
        signature_options,
    )
    .await
    .map_err(|e| CrabCakesError::Sigv4Verification(e.to_string()))?;

    Ok((
        parts,
        body,
        SigV4AuthenticatorResponse::builder()
            .principal(auth.principal().clone())
            .session_data(SessionData::new())
            .build()?,
    ))
}

impl AuthContext {
    /// Extract authentication information from request headers
    /// For now, we use a simplified approach:
    /// - Check for x-amz-user header (custom header for testing)
    /// - Check for AWS_ACCESS_KEY_ID from Authorization header (basic parsing)
    /// - Default to anonymous if no auth found
    pub fn from_request(req: &Request<hyper::body::Incoming>) -> Self {
        // Check for custom x-amz-user header (simplified for testing)
        if let Some(user_header) = req.headers().get("x-amz-user")
            && let Ok(username) = user_header.to_str()
        {
            debug!(username = %username, "Authenticated user from x-amz-user header");
            let arn = format!("arn:aws:iam:::user/{}", username);
            return Self {
                principal: Principal::Aws(PrincipalId::String(arn)),
                username: Some(username.to_string()),
            };
        }

        // Check Authorization header for AWS credentials
        if let Some(auth_header) = req.headers().get(AUTHORIZATION)
            && let Ok(auth_str) = auth_header.to_str()
        {
            // Basic parsing of AWS Signature V4 format
            // Format: AWS4-HMAC-SHA256 Credential=ACCESS_KEY/date/region/service/aws4_request
            if let Some(username) = Self::parse_access_key(auth_str) {
                debug!(username = %username, "Authenticated user from Authorization header");
                return Self {
                    principal: Principal::Aws(PrincipalId::String(format!(
                        "arn:aws:iam:::user/{}",
                        username
                    ))),
                    username: Some(username.clone()),
                };
            }
        }

        // Default to anonymous
        debug!("No authentication found, using anonymous principal");
        Self {
            principal: Principal::Wildcard,
            username: None,
        }
    }

    /// Parse access key from Authorization header
    /// This is a simplified parser - in production you'd want full AWS Signature V4 validation
    fn parse_access_key(auth_str: &str) -> Option<String> {
        // Look for Credential= in the auth string
        if let Some(cred_start) = auth_str.find("Credential=") {
            let after_cred = &auth_str[cred_start + 11..]; // Skip "Credential="
            if let Some(slash_pos) = after_cred.find('/') {
                let access_key = &after_cred[..slash_pos];
                return Some(access_key.to_string());
            }
        }
        None
    }

    /// Build an IAM Request for policy evaluation
    pub fn build_iam_request(
        &self,
        action: S3Action,
        bucket: Option<&str>,
        key: Option<&str>,
    ) -> Result<IAMRequest, Box<dyn std::error::Error>> {
        // Construct resource ARN
        let resource_arn_str = match (bucket, key) {
            (Some(b), Some(k)) => format!("arn:aws:s3:::{}/{}", b, k),
            (Some(b), None) => format!("arn:aws:s3:::{}", b),
            _ => "arn:aws:s3:::*".to_string(),
        };

        debug!(
            principal = ?self.principal,
            action = %action,
            resource = %resource_arn_str,
            "Building IAM request"
        );

        let resource_arn = Arn::parse(&resource_arn_str)?;

        // Build context with username for variable interpolation
        let mut context = Context::new();
        if let Some(username) = &self.username {
            context.insert(
                "aws:username".to_string(),
                ContextValue::String(username.clone()),
            );
        }

        Ok(IAMRequest {
            principal: self.principal.clone(),
            action: action.to_string(),
            resource: resource_arn,
            context,
        })
    }
}

/// Map S3 HTTP operations to IAM actions
pub fn http_method_to_s3_action(
    method: &Method,
    path: &str,
    query: &str,
    is_bucket_operation: bool,
) -> Option<S3Action> {
    match (method, path, query, is_bucket_operation) {
        // Multipart upload operations (must come before general POST cases)
        (&Method::POST, _, q, false) if q.contains("uploads") && !q.contains("uploadId") => {
            Some(S3Action::PutObject) // InitiateMultipartUpload
        }
        (&Method::PUT, _, q, false) if q.contains("uploadId") && q.contains("partNumber") => {
            Some(S3Action::PutObject) // UploadPart
        }
        (&Method::DELETE, _, q, false) if q.contains("uploadId") => {
            Some(S3Action::AbortMultipartUpload)
        }
        (&Method::GET, _, q, true) if q.contains("uploads") => {
            Some(S3Action::ListBucketMultipartUploads)
        }
        (&Method::GET, _, q, false) if q.contains("uploadId") => {
            Some(S3Action::ListMultipartUploadParts)
        }
        (&Method::POST, _, q, false) if q.contains("uploadId") => Some(S3Action::PutObject), // CompleteMultipartUpload

        // Object tagging operations
        (&Method::GET, _, q, false) if q.contains("tagging") => Some(S3Action::GetObjectTagging),
        (&Method::PUT, _, q, false) if q.contains("tagging") => Some(S3Action::PutObjectTagging),
        (&Method::DELETE, _, q, false) if q.contains("tagging") => {
            Some(S3Action::DeleteObjectTagging)
        }
        (&Method::GET, _, q, false) if q.contains("attributes") => {
            Some(S3Action::GetObjectAttributes)
        }

        // Special cases
        (&Method::GET, _, q, _) if q.contains("list-type=2") => Some(S3Action::ListBucket),
        (&Method::GET, _, q, _) if q.contains("location") => Some(S3Action::GetBucketLocation),
        (&Method::GET, "/", _, _) => Some(S3Action::ListAllMyBuckets),
        (&Method::POST, _, q, _) if q.contains("delete") => Some(S3Action::DeleteObject), // DeleteObjects batch

        // Bucket operations
        (&Method::GET, _, _, true) => Some(S3Action::ListBucket), // GET on bucket (list operation)
        (&Method::HEAD, _, _, true) => Some(S3Action::ListBucket), // HeadBucket uses ListBucket permission
        (&Method::PUT, _, _, true) => Some(S3Action::CreateBucket),
        (&Method::DELETE, _, _, true) => Some(S3Action::DeleteBucket),

        // Object operations
        (&Method::GET, _, _, false) => Some(S3Action::GetObject),
        (&Method::HEAD, _, _, false) => Some(S3Action::GetObject), // HeadObject uses GetObject permission
        (&Method::PUT, _, _, false) => Some(S3Action::PutObject),
        (&Method::DELETE, _, _, false) => Some(S3Action::DeleteObject),

        _ => None, //"s3:Unknown",
    }
}

/// Extract bucket and key from path
/// Returns (bucket, key) where key is None for bucket-level operations
pub fn extract_bucket_and_key(path: &str) -> (Option<String>, Option<String>) {
    let path = path.trim_start_matches('/');

    if path.is_empty() {
        return (None, None);
    }

    // Split on first slash
    if let Some(slash_pos) = path.find('/') {
        let bucket = &path[..slash_pos];
        let key = &path[slash_pos + 1..];

        if key.is_empty() {
            // Path ends with slash: /bucket/
            (Some(bucket.to_string()), None)
        } else {
            // Path has key: /bucket/key
            (Some(bucket.to_string()), Some(key.to_string()))
        }
    } else {
        // No slash - just bucket or file at root
        // Check if it looks like a file (has extension)
        if path.contains('.') {
            (None, Some(path.to_string()))
        } else {
            (Some(path.to_string()), None)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::DEFAULT_REGION;

    use super::*;

    #[test]
    fn test_parse_access_key() {
        let auth = "AWS4-HMAC-SHA256 Credential=alice/20231201/crabcakes/s3/aws4_request";
        assert_eq!(
            AuthContext::parse_access_key(auth),
            Some("alice".to_string())
        );
    }

    #[test]
    fn test_extract_bucket_and_key() {
        assert_eq!(
            extract_bucket_and_key("/bucket1/test.txt"),
            (Some("bucket1".to_string()), Some("test.txt".to_string()))
        );
        assert_eq!(
            extract_bucket_and_key("/bucket1/"),
            (Some("bucket1".to_string()), None)
        );
        assert_eq!(
            extract_bucket_and_key("/bucket1"),
            (Some("bucket1".to_string()), None)
        );
        assert_eq!(
            extract_bucket_and_key("/test.txt"),
            (None, Some("test.txt".to_string()))
        );
        assert_eq!(extract_bucket_and_key("/"), (None, None));
    }

    #[test]
    fn test_http_method_to_s3_action() {
        assert_eq!(
            http_method_to_s3_action(&Method::GET, "/", "", false).expect("Failed to convert"),
            S3Action::ListAllMyBuckets
        );
        assert_eq!(
            http_method_to_s3_action(&Method::GET, "/bucket1", "list-type=2", false)
                .expect("Failed to convert"),
            S3Action::ListBucket
        );
        assert_eq!(
            http_method_to_s3_action(&Method::GET, "/bucket1/test.txt", "", false)
                .expect("Failed to convert"),
            S3Action::GetObject,
        );
        assert_eq!(
            http_method_to_s3_action(&Method::HEAD, "/bucket1/test.txt", "", false)
                .expect("Failed to convert"),
            S3Action::GetObject
        );
        assert_eq!(
            http_method_to_s3_action(&Method::PUT, "/bucket1/test.txt", "", false)
                .expect("Failed to convert"),
            S3Action::PutObject
        );
        assert_eq!(
            http_method_to_s3_action(&Method::DELETE, "/bucket1/test.txt", "", false)
                .expect("Failed to convert"),
            S3Action::DeleteObject
        );
        // Bucket operations
        assert_eq!(
            http_method_to_s3_action(&Method::HEAD, "/bucket1", "", true)
                .expect("Failed to convert"),
            S3Action::ListBucket
        );
        assert_eq!(
            http_method_to_s3_action(&Method::PUT, "/bucket1", "", true)
                .expect("Failed to convert"),
            S3Action::CreateBucket
        );
        assert_eq!(
            http_method_to_s3_action(&Method::DELETE, "/bucket1", "", true)
                .expect("Failed to convert"),
            S3Action::DeleteBucket
        );
        // GetBucketLocation
        assert_eq!(
            http_method_to_s3_action(&Method::GET, "/bucket1", "location", true)
                .expect("Failed to convert"),
            S3Action::GetBucketLocation
        );
    }

    #[tokio::test]
    async fn test_verify_sigv4_missing_auth_header_required() {
        let cred_store = CredentialStore::new_test().await;
        let db_conn = crate::db::initialize_in_memory_database().await.unwrap();
        let db = Arc::new(DBService::new(Arc::new(db_conn)));

        // Create request without Authorization header
        let request = http::Request::builder()
            .method(&Method::GET)
            .uri("http://localhost:9000/bucket1/test.txt")
            .body(vec![])
            .unwrap();

        // Verify with signature required - should fail
        let result = verify_sigv4(request, cred_store, db, DEFAULT_REGION).await;

        assert!(
            result.is_err(),
            "Missing auth header should fail when required"
        );
        if let Err(CrabCakesError::NoAuthenticationSupplied(_)) = result {
            // Expected error type
        } else {
            panic!("Expected NoAuthenticationSupplied error");
        }
    }

    #[tokio::test]
    async fn test_verify_sigv4_missing_auth_header_not_required() {
        let cred_store = CredentialStore::new_test().await;
        let db_conn = crate::db::initialize_in_memory_database().await.unwrap();
        let db = Arc::new(DBService::new(Arc::new(db_conn)));

        // Create request without Authorization header
        let request = http::Request::builder()
            .method(&Method::GET)
            .uri("http://localhost:9000/bucket1/test.txt")
            .body(vec![])
            .unwrap();

        // Verify with signature not required - should return error indicating no auth
        let result = verify_sigv4(request, cred_store, db, DEFAULT_REGION).await;

        assert!(
            result.is_err(),
            "Should return error for missing auth even when not required"
        );
        if let Err(CrabCakesError::NoAuthenticationSupplied(_)) = result {
            // Expected error type
        } else {
            panic!("Expected NoAuthenticationSupplied error");
        }
    }

    #[tokio::test]
    async fn test_verify_sigv4_with_malformed_auth_header() {
        let cred_store = CredentialStore::new_test().await;
        let db_conn = crate::db::initialize_in_memory_database().await.unwrap();
        let db = Arc::new(DBService::new(Arc::new(db_conn)));

        // Create request with malformed Authorization header
        let request = http::Request::builder()
            .method(&Method::GET)
            .uri("http://localhost:9000/bucket1/test.txt")
            .header(AUTHORIZATION, "Not a valid signature")
            .body(vec![])
            .unwrap();

        // Verify - should fail
        let result = verify_sigv4(request, cred_store, db, DEFAULT_REGION).await;

        assert!(
            result.is_err(),
            "Malformed auth header should fail verification"
        );
    }
}
