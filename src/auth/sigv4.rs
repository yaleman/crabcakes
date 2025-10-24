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
use iam_rs::{Arn, Context, IAMRequest, Principal, PrincipalId};
use scratchstack_aws_principal::{self, SessionData};
use scratchstack_aws_signature::auth::SigV4AuthenticatorResponse;
use scratchstack_aws_signature::{
    GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, NO_ADDITIONAL_SIGNED_HEADERS,
    SignatureOptions, service_for_signing_key_fn, sigv4_validate_request,
};
use tracing::{debug, trace, warn};
use secret_string::SecretString;
use tower::BoxError;

use crate::constants::{MOCK_ACCOUNT_ID, S3, S3Action};
use crate::credentials::CredentialStore;
use crate::db::DBService;
use crate::error::CrabCakesError;
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
    credentials_store: Arc<CredentialStore>,
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
        let configured_region = region.to_string();
        move |request: GetSigningKeyRequest| {
            let cred_store = cred_store.clone();
            let db_service = db_service.clone();
            let configured_region = configured_region.clone();
            async move {
                let access_key = request.access_key().to_string();
                debug!(access_key = %access_key, "Looking up signing key");

                // Check if the region from the credential scope is empty or doesn't match
                let credential_region = request.region();
                if credential_region.is_empty() {
                    warn!(
                        access_key = %access_key,
                        configured_region = %configured_region,
                        "Client sent empty region in credential scope (Credential=...//)! This will cause signature mismatch. Client should use region: {}",
                        configured_region
                    );
                } else if credential_region != configured_region {
                    warn!(
                        access_key = %access_key,
                        credential_region = %credential_region,
                        configured_region = %configured_region,
                        "Region mismatch: client sent '{}' but server expects '{}'. This will cause signature verification to fail.",
                        credential_region,
                        configured_region
                    );
                }

                // Try to get the credential from the permanent store first
                let secret_access_key = match cred_store.get_credential(&access_key).await {
                    Some(secret) => {
                        debug!(access_key = %access_key, "Found credential in permanent store");
                        secret
                    }
                    None => {
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
                            return Err(BoxError::from(
                                "Temporary credentials expired".to_string(),
                            ));
                        }

                        debug!(access_key = %access_key, "Found valid temporary credential in database");
                        SecretString::new(temp_cred.secret_access_key)
                    }
                };

                // Convert secret key to KSecretKey
                trace!(access_key = %access_key, secret_key_length = secret_access_key.len(), "About to parse secret key");
                let secret_key =
                    KSecretKey::from_str(secret_access_key.value()).map_err(|err| {
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

                debug!("returning principal: {:?}", principal);

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
    pub fn from_request<B>(req: &Request<B>) -> Self {
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
            bucket = ?bucket,
            key = ?key,
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
                iam_rs::ContextValue::String(username.clone()),
            );
        }

        let res = IAMRequest {
            principal: self.principal.clone(),
            action: action.to_string(),
            resource: resource_arn,
            context,
        };
        debug!(?res, "Constructed IAM request");
        Ok(res)
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

        // Bucket website configuration operations
        (&Method::GET, _, q, true) if q.contains("website") => Some(S3Action::GetBucketWebsite),
        (&Method::PUT, _, q, true) if q.contains("website") => Some(S3Action::PutBucketWebsite),
        (&Method::DELETE, _, q, true) if q.contains("website") => {
            Some(S3Action::DeleteBucketWebsite)
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
    use crate::{
        constants::{AWS4_HMAC_SHA256, DEFAULT_REGION, TEST_ALLOWED_BUCKET},
        logging::setup_test_logging,
    };

    use super::*;

    #[test]
    fn test_extract_bucket_and_key() {
        assert_eq!(
            extract_bucket_and_key("/bucket1/test.txt"),
            (
                Some(TEST_ALLOWED_BUCKET.to_string()),
                Some("test.txt".to_string())
            )
        );
        assert_eq!(
            extract_bucket_and_key("/bucket1/"),
            (Some(TEST_ALLOWED_BUCKET.to_string()), None)
        );
        assert_eq!(
            extract_bucket_and_key("/bucket1"),
            (Some(TEST_ALLOWED_BUCKET.to_string()), None)
        );
        assert_eq!(
            extract_bucket_and_key("/test.txt"),
            (None, Some("test.txt".to_string()))
        );
        assert_eq!(extract_bucket_and_key("/"), (None, None));

        // nested path
        assert_eq!(
            extract_bucket_and_key("/bucket/dir1/dir2/file.txt"),
            (
                Some("bucket".to_string()),
                Some("dir1/dir2/file.txt".to_string())
            )
        );

        // extract with multiple_dots
        assert_eq!(
            extract_bucket_and_key("/bucket/my.file.tar.gz"),
            (
                Some("bucket".to_string()),
                Some("my.file.tar.gz".to_string())
            )
        );
        // bucket_without_extension
        // Without a dot, should be treated as bucket
        assert_eq!(
            extract_bucket_and_key("/mybucket"),
            (Some("mybucket".to_string()), None)
        );
    }

    #[test]
    fn test_http_method_to_s3_action() {
        setup_test_logging();
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
        setup_test_logging();
        let cred_store = CredentialStore::new_test().await;
        let db_conn = crate::db::initialize_in_memory_database().await;
        let db = Arc::new(DBService::new(Arc::new(db_conn)));

        // Create request without Authorization header
        let request = http::Request::builder()
            .method(&Method::GET)
            .uri("http://localhost:9000/bucket1/test.txt")
            .body(vec![])
            .expect("Failed to build test request");

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
        setup_test_logging();
        let cred_store = CredentialStore::new_test().await;
        let db_conn = crate::db::initialize_in_memory_database().await;
        let db = Arc::new(DBService::new(Arc::new(db_conn)));

        // Create request without Authorization header
        let request = http::Request::builder()
            .method(&Method::GET)
            .uri("http://localhost:9000/bucket1/test.txt")
            .body(vec![])
            .expect("Failed to build test request");

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
        setup_test_logging();
        let cred_store = CredentialStore::new_test().await;
        let db_conn = crate::db::initialize_in_memory_database().await;
        let db = Arc::new(DBService::new(Arc::new(db_conn)));

        // Create request with malformed Authorization header
        let request = http::Request::builder()
            .method(&Method::GET)
            .uri("http://localhost:9000/bucket1/test.txt")
            .header(AUTHORIZATION, "Not a valid signature")
            .body(vec![])
            .expect("Failed to build test request");

        // Verify - should fail
        let result = verify_sigv4(request, cred_store, db, DEFAULT_REGION).await;

        assert!(
            result.is_err(),
            "Malformed auth header should fail verification"
        );
    }

    // AuthContext::from_request() tests
    #[test]
    fn test_auth_context_from_x_amz_user_header() {
        setup_test_logging();
        let request = Request::builder()
            .header("x-amz-user", "testuser")
            .body(())
            .expect("Failed to build test request");

        let auth_context = AuthContext::from_request(&request);

        assert_eq!(auth_context.username, Some("testuser".to_string()));
        match auth_context.principal {
            Principal::Aws(PrincipalId::String(arn)) => {
                assert_eq!(arn, "arn:aws:iam:::user/testuser");
            }
            _ => panic!("Expected AWS principal"),
        }
    }

    #[test]
    fn test_auth_context_from_authorization_header() {
        setup_test_logging();
        let request = Request::builder()
            .header(
                AUTHORIZATION,
                format!(
                    "{} Credential=alice/20231201/crabcakes/s3/aws4_request",
                    AWS4_HMAC_SHA256
                ),
            )
            .body(())
            .expect("Failed to build test request");

        let auth_context = AuthContext::from_request(&request);

        assert_eq!(auth_context.username, Some("alice".to_string()));
        match auth_context.principal {
            Principal::Aws(PrincipalId::String(arn)) => {
                assert_eq!(arn, "arn:aws:iam:::user/alice");
            }
            _ => panic!("Expected AWS principal"),
        }
    }

    #[test]
    fn test_auth_context_anonymous_fallback() {
        setup_test_logging();
        let request = Request::builder()
            .body(())
            .expect("Failed to build test request");

        let auth_context = AuthContext::from_request(&request);

        assert_eq!(auth_context.username, None);
        assert!(matches!(auth_context.principal, Principal::Wildcard));
    }

    #[test]
    fn test_auth_context_invalid_authorization_header() {
        setup_test_logging();
        let request = Request::builder()
            .header(AUTHORIZATION, "InvalidAuthFormat")
            .body(())
            .expect("Failed to build test request");

        let auth_context = AuthContext::from_request(&request);

        // Should fall back to anonymous since parsing failed
        assert_eq!(auth_context.username, None);
        assert!(matches!(auth_context.principal, Principal::Wildcard));
    }

    // AuthContext::build_iam_request() tests
    #[test]
    fn test_build_iam_request_with_bucket_and_key() {
        setup_test_logging();
        let auth_context = AuthContext {
            principal: Principal::Aws(PrincipalId::String(
                "arn:aws:iam:::user/testuser".to_string(),
            )),
            username: Some("testuser".to_string()),
        };

        let iam_request = auth_context
            .build_iam_request(S3Action::GetObject, Some("mybucket"), Some("mykey.txt"))
            .expect("Should build IAM request");

        assert_eq!(iam_request.action, "s3:GetObject");
        assert_eq!(
            iam_request.resource.to_string(),
            "arn:aws:s3:::mybucket/mykey.txt"
        );
        assert!(iam_request.context.get("aws:username").is_some());
    }

    #[test]
    fn test_build_iam_request_bucket_only() {
        setup_test_logging();
        let auth_context = AuthContext {
            principal: Principal::Aws(PrincipalId::String(
                "arn:aws:iam:::user/testuser".to_string(),
            )),
            username: Some("testuser".to_string()),
        };

        let iam_request = auth_context
            .build_iam_request(S3Action::ListBucket, Some("mybucket"), None)
            .expect("Should build IAM request");

        assert_eq!(iam_request.action, "s3:ListBucket");
        assert_eq!(iam_request.resource.to_string(), "arn:aws:s3:::mybucket");
    }

    #[test]
    fn test_build_iam_request_wildcard() {
        setup_test_logging();
        let auth_context = AuthContext {
            principal: Principal::Wildcard,
            username: None,
        };

        let iam_request = auth_context
            .build_iam_request(S3Action::ListAllMyBuckets, None, None)
            .expect("Should build IAM request");

        assert_eq!(iam_request.action, "s3:ListAllMyBuckets");
        assert_eq!(iam_request.resource.to_string(), "arn:aws:s3:::*");
    }

    #[test]
    fn test_build_iam_request_with_username_context() {
        setup_test_logging();
        let auth_context = AuthContext {
            principal: Principal::Aws(PrincipalId::String("arn:aws:iam:::user/alice".to_string())),
            username: Some("alice".to_string()),
        };

        let iam_request = auth_context
            .build_iam_request(S3Action::PutObject, Some("bucket"), Some("key"))
            .expect("Should build IAM request");

        // Check context has username
        let username_value = iam_request.context.get("aws:username");
        assert!(username_value.is_some());
        if let Some(iam_rs::ContextValue::String(username)) = username_value {
            assert_eq!(username, "alice");
        } else {
            panic!("Expected username context value");
        }
    }

    #[test]
    fn test_build_iam_request_without_username_context() {
        setup_test_logging();
        let auth_context = AuthContext {
            principal: Principal::Wildcard,
            username: None,
        };

        let iam_request = auth_context
            .build_iam_request(S3Action::GetObject, Some("bucket"), Some("key"))
            .expect("Should build IAM request");

        // Context should not have username
        assert!(iam_request.context.get("aws:username").is_none());
    }

    // http_method_to_s3_action() multipart operation tests
    #[test]
    fn test_http_method_initiate_multipart() {
        setup_test_logging();
        assert_eq!(
            http_method_to_s3_action(&Method::POST, "/bucket/key", "uploads", false)
                .expect("Should map to PutObject"),
            S3Action::PutObject
        );
    }

    #[test]
    fn test_http_method_upload_part() {
        setup_test_logging();
        assert_eq!(
            http_method_to_s3_action(
                &Method::PUT,
                "/bucket/key",
                "uploadId=abc&partNumber=1",
                false
            )
            .expect("Should map to PutObject"),
            S3Action::PutObject
        );
    }

    #[test]
    fn test_http_method_abort_multipart() {
        setup_test_logging();
        assert_eq!(
            http_method_to_s3_action(&Method::DELETE, "/bucket/key", "uploadId=abc", false)
                .expect("Should map to AbortMultipartUpload"),
            S3Action::AbortMultipartUpload
        );
    }

    #[test]
    fn test_http_method_list_multipart_uploads() {
        setup_test_logging();
        assert_eq!(
            http_method_to_s3_action(&Method::GET, "/bucket", "uploads", true)
                .expect("Should map to ListBucketMultipartUploads"),
            S3Action::ListBucketMultipartUploads
        );
    }

    #[test]
    fn test_http_method_list_multipart_parts() {
        setup_test_logging();
        assert_eq!(
            http_method_to_s3_action(&Method::GET, "/bucket/key", "uploadId=abc", false)
                .expect("Should map to ListMultipartUploadParts"),
            S3Action::ListMultipartUploadParts
        );
    }

    #[test]
    fn test_http_method_complete_multipart() {
        setup_test_logging();
        assert_eq!(
            http_method_to_s3_action(&Method::POST, "/bucket/key", "uploadId=abc", false)
                .expect("Should map to PutObject"),
            S3Action::PutObject
        );
    }

    // http_method_to_s3_action() tagging operation tests
    #[test]
    fn test_http_method_get_object_tagging() {
        setup_test_logging();
        assert_eq!(
            http_method_to_s3_action(&Method::GET, "/bucket/key", "tagging", false)
                .expect("Should map to GetObjectTagging"),
            S3Action::GetObjectTagging
        );
    }

    #[test]
    fn test_http_method_put_object_tagging() {
        setup_test_logging();
        assert_eq!(
            http_method_to_s3_action(&Method::PUT, "/bucket/key", "tagging", false)
                .expect("Should map to PutObjectTagging"),
            S3Action::PutObjectTagging
        );
    }

    #[test]
    fn test_http_method_delete_object_tagging() {
        setup_test_logging();
        assert_eq!(
            http_method_to_s3_action(&Method::DELETE, "/bucket/key", "tagging", false)
                .expect("Should map to DeleteObjectTagging"),
            S3Action::DeleteObjectTagging
        );
    }

    #[test]
    fn test_http_method_get_object_attributes() {
        setup_test_logging();
        assert_eq!(
            http_method_to_s3_action(&Method::GET, "/bucket/key", "attributes", false)
                .expect("Should map to GetObjectAttributes"),
            S3Action::GetObjectAttributes
        );
    }

    #[test]
    fn test_http_method_delete_objects_batch() {
        setup_test_logging();
        assert_eq!(
            http_method_to_s3_action(&Method::POST, "/bucket", "delete", true)
                .expect("Should map to DeleteObject"),
            S3Action::DeleteObject
        );
    }

    // parse_access_key() edge case tests
    #[test]
    fn test_parse_access_key() {
        setup_test_logging();
        //valid case
        let auth = format!(
            "{} Credential=alice/20231201/crabcakes/s3/aws4_request",
            AWS4_HMAC_SHA256
        );
        assert_eq!(
            AuthContext::parse_access_key(&auth),
            Some("alice".to_string())
        );

        // missing_credential
        let auth = format!("{} NoCredentialHere", AWS4_HMAC_SHA256);
        assert_eq!(AuthContext::parse_access_key(&auth), None);

        // missing_slash
        let auth = format!("{} Credential=alice_no_slash", AWS4_HMAC_SHA256);
        assert_eq!(AuthContext::parse_access_key(&auth), None);
        // empty_string
        assert_eq!(AuthContext::parse_access_key(""), None);
    }
}
