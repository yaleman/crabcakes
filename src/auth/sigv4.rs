//! AWS Signature Version 4 authentication and authorization.
//!
//! Provides signature verification for both standard and streaming S3 requests,
//! along with IAM request context building for policy evaluation.

use std::str::FromStr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use http::HeaderValue;
use hyper::{Request, header::AUTHORIZATION};
use iam_rs::{Arn, Context, ContextValue, IAMRequest, Principal, PrincipalId};
use scratchstack_aws_principal;
use scratchstack_aws_signature::{
    GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, NO_ADDITIONAL_SIGNED_HEADERS,
    SignatureOptions, service_for_signing_key_fn, sigv4_validate_request,
};
use tokio::sync::RwLock;
use tower::BoxError;
use tracing::{debug, trace};

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
) -> Result<VerifiedRequest, CrabCakesError> {
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
                    if temp_cred.expires_at < chrono::Utc::now().naive_utc() {
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
    let (_parts, _body, auth) = sigv4_validate_request(
        req,
        region,
        "s3",
        &mut service,
        chrono::Utc::now(),
        &NO_ADDITIONAL_SIGNED_HEADERS,
        signature_options,
    )
    .await
    .map_err(|e| CrabCakesError::Sigv4Verification(e.to_string()))?;

    // Extract username from principal identities
    let access_key_id = auth
        .principal()
        .as_slice()
        .iter()
        .find_map(|identity| match identity {
            scratchstack_aws_principal::PrincipalIdentity::User(user) => {
                Some(user.user_name().to_string())
            }
            _ => None,
        })
        .ok_or(CrabCakesError::NoUserIdInPrincipal)?;

    Ok(VerifiedRequest {
        access_key_id,
        principal: auth.principal().clone(),
    })
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
        action: &str,
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
    method: &str,
    path: &str,
    query: &str,
    is_bucket_operation: bool,
) -> &'static str {
    match (method, path, query, is_bucket_operation) {
        // Multipart upload operations (must come before general POST cases)
        ("POST", _, q, false) if q.contains("uploads") && !q.contains("uploadId") => {
            "s3:PutObject" // InitiateMultipartUpload
        }
        ("PUT", _, q, false) if q.contains("uploadId") && q.contains("partNumber") => {
            "s3:PutObject" // UploadPart
        }
        ("DELETE", _, q, false) if q.contains("uploadId") => "s3:AbortMultipartUpload",
        ("GET", _, q, true) if q.contains("uploads") => "s3:ListBucketMultipartUploads",
        ("GET", _, q, false) if q.contains("uploadId") => "s3:ListMultipartUploadParts",
        ("POST", _, q, false) if q.contains("uploadId") => "s3:PutObject", // CompleteMultipartUpload

        // Object tagging operations
        ("GET", _, q, false) if q.contains("tagging") => "s3:GetObjectTagging",
        ("PUT", _, q, false) if q.contains("tagging") => "s3:PutObjectTagging",
        ("DELETE", _, q, false) if q.contains("tagging") => "s3:DeleteObjectTagging",
        ("GET", _, q, false) if q.contains("attributes") => "s3:GetObjectAttributes",

        // Special cases
        ("GET", _, q, _) if q.contains("list-type=2") => "s3:ListBucket",
        ("GET", _, q, _) if q.contains("location") => "s3:GetBucketLocation",
        ("GET", "/", _, _) => "s3:ListAllMyBuckets",
        ("POST", _, q, _) if q.contains("delete") => "s3:DeleteObject", // DeleteObjects batch

        // Bucket operations
        ("GET", _, _, true) => "s3:ListBucket", // GET on bucket (list operation)
        ("HEAD", _, _, true) => "s3:ListBucket", // HeadBucket uses ListBucket permission
        ("PUT", _, _, true) => "s3:CreateBucket",
        ("DELETE", _, _, true) => "s3:DeleteBucket",

        // Object operations
        ("GET", _, _, false) => "s3:GetObject",
        ("HEAD", _, _, false) => "s3:GetObject", // HeadObject uses GetObject permission
        ("PUT", _, _, false) => "s3:PutObject",
        ("DELETE", _, _, false) => "s3:DeleteObject",

        _ => "s3:Unknown",
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

/// Parse AWS Authorization header to extract components
/// Format: AWS4-HMAC-SHA256 Credential=ACCESS_KEY/DATE/REGION/SERVICE/aws4_request, SignedHeaders=..., Signature=...
fn parse_authorization_header(
    auth_header: &str,
) -> Result<(String, String, Vec<String>, String), CrabCakesError> {
    // Extract credential
    let credential = auth_header
        .split("Credential=")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .ok_or_else(|| {
            CrabCakesError::Sigv4Verification(
                "Missing Credential in Authorization header".to_string(),
            )
        })?;

    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5 {
        return Err(CrabCakesError::Sigv4Verification(
            "Invalid Credential format".to_string(),
        ));
    }
    let access_key = parts[0].to_string();
    let date = parts[1].to_string();
    let _region = parts[2].to_string();

    // Extract signed headers
    let signed_headers_str = auth_header
        .split("SignedHeaders=")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .ok_or_else(|| {
            CrabCakesError::Sigv4Verification(
                "Missing SignedHeaders in Authorization header".to_string(),
            )
        })?;
    let signed_headers: Vec<String> = signed_headers_str
        .split(';')
        .map(|s| s.to_string())
        .collect();

    // Extract signature
    let signature = auth_header
        .split("Signature=")
        .nth(1)
        .ok_or_else(|| {
            CrabCakesError::Sigv4Verification(
                "Missing Signature in Authorization header".to_string(),
            )
        })?
        .trim()
        .to_string();

    Ok((access_key, date, signed_headers, signature))
}

/// Build canonical request for streaming uploads
/// Uses the literal x-amz-content-sha256 header value instead of computing SHA256
fn build_canonical_request(
    parts: &http::request::Parts,
    signed_headers: &[String],
    body_hash: &str,
) -> String {
    let mut canonical = String::new();

    // Method
    canonical.push_str(parts.method.as_str());
    canonical.push('\n');

    // Canonical URI (S3-specific: don't double-encode)
    canonical.push_str(parts.uri.path());
    canonical.push('\n');

    // Canonical query string (must be sorted by parameter name)
    if let Some(query) = parts.uri.query() {
        let mut params: Vec<&str> = query.split('&').collect();
        params.sort_unstable();
        canonical.push_str(&params.join("&"));
    }
    canonical.push('\n');

    // Canonical headers (only signed headers, sorted)
    for header_name in signed_headers {
        if let Some(header_value) = parts.headers.get(header_name) {
            canonical.push_str(header_name);
            canonical.push(':');
            if let Ok(value_str) = header_value.to_str() {
                canonical.push_str(value_str.trim());
            }
            canonical.push('\n');
        }
    }
    canonical.push('\n');

    // Signed headers list (must match what client sent in Authorization header)
    canonical.push_str(&signed_headers.join(";"));
    canonical.push('\n');

    // Body hash (literal value from x-amz-content-sha256)
    canonical.push_str(body_hash);

    debug!("Canonical request for streaming:\n{}", canonical);
    canonical
}

/// Compute string to sign
fn compute_string_to_sign(
    timestamp: &DateTime<Utc>,
    region: &str,
    canonical_request_hash: &str,
) -> String {
    let credential_scope = format!("{}/{}/s3/aws4_request", timestamp.format("%Y%m%d"), region);

    format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        timestamp.format("%Y%m%dT%H%M%SZ"),
        credential_scope,
        canonical_request_hash
    )
}

/// Verify streaming signature for AWS SigV4
pub async fn verify_streaming_sigv4(
    parts: http::request::Parts,
    credentials_store: Arc<RwLock<CredentialStore>>,
    region: &str,
) -> Result<VerifiedRequest, CrabCakesError> {
    // Get Authorization header
    let auth_header = parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            CrabCakesError::NoAuthenticationSupplied("Missing Authorization header".to_string())
        })?;

    // Parse Authorization header
    let (access_key_id, _date_str, signed_headers, provided_signature) =
        parse_authorization_header(auth_header)?;

    debug!(
        access_key = %access_key_id,
        signed_headers = ?signed_headers,
        "Verifying streaming signature"
    );

    // Get x-amz-content-sha256 header value (literal string to use in canonical request)
    let body_hash = parts
        .headers
        .get("x-amz-content-sha256")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            CrabCakesError::Sigv4Verification("Missing x-amz-content-sha256 header".to_string())
        })?;

    // Get timestamp from x-amz-date header
    let timestamp_str = parts
        .headers
        .get("x-amz-date")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            CrabCakesError::Sigv4Verification("Missing x-amz-date header".to_string())
        })?;

    let timestamp = chrono::NaiveDateTime::parse_from_str(timestamp_str, "%Y%m%dT%H%M%SZ")
        .map_err(|e| {
            CrabCakesError::Sigv4Verification(format!("Invalid x-amz-date format: {}", e))
        })?
        .and_utc();

    // Build canonical request using literal body hash
    let canonical_request = build_canonical_request(&parts, &signed_headers, body_hash);

    // Compute SHA256 of canonical request
    let canonical_request_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(canonical_request.as_bytes());
        format!("{:x}", hasher.finalize())
    };

    // Compute string to sign
    let string_to_sign = compute_string_to_sign(&timestamp, region, &canonical_request_hash);
    debug!("String to sign:\n{}", string_to_sign);

    // Get secret key from credential store
    let secret_access_key = credentials_store
        .read()
        .await
        .get_credential(&access_key_id)
        .await
        .ok_or(CrabCakesError::InvalidCredential)?;

    // Derive signing key
    let secret_key = KSecretKey::from_str(&secret_access_key)
        .map_err(|e| CrabCakesError::Sigv4Verification(format!("Invalid secret key: {}", e)))?;

    let signing_key = secret_key.to_ksigning(timestamp.date_naive(), region, "s3");

    // Compute expected signature
    let expected_signature = {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(signing_key.as_ref())
            .map_err(|e| CrabCakesError::Sigv4Verification(format!("HMAC error: {}", e)))?;
        mac.update(string_to_sign.as_bytes());
        format!("{:x}", mac.finalize().into_bytes())
    };

    debug!(expected = %expected_signature, provided = %provided_signature, "Comparing signatures");

    // Compare signatures
    if expected_signature != provided_signature {
        return Err(CrabCakesError::Sigv4Verification(format!(
            "Signature mismatch: expected '{}', got '{}'",
            expected_signature, provided_signature
        )));
    }

    // Create principal
    let principal =
        scratchstack_aws_principal::User::new("aws", MOCK_ACCOUNT_ID, "/", &access_key_id)
            .map_err(|e| {
                CrabCakesError::Sigv4Verification(format!("Failed to create principal: {}", e))
            })?;

    Ok(VerifiedRequest {
        access_key_id,
        principal: principal.into(),
    })
}

#[cfg(test)]
mod tests {
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
            http_method_to_s3_action("GET", "/", "", false),
            "s3:ListAllMyBuckets"
        );
        assert_eq!(
            http_method_to_s3_action("GET", "/bucket1", "list-type=2", false),
            "s3:ListBucket"
        );
        assert_eq!(
            http_method_to_s3_action("GET", "/bucket1/test.txt", "", false),
            "s3:GetObject"
        );
        assert_eq!(
            http_method_to_s3_action("HEAD", "/bucket1/test.txt", "", false),
            "s3:GetObject"
        );
        assert_eq!(
            http_method_to_s3_action("PUT", "/bucket1/test.txt", "", false),
            "s3:PutObject"
        );
        assert_eq!(
            http_method_to_s3_action("DELETE", "/bucket1/test.txt", "", false),
            "s3:DeleteObject"
        );
        // Bucket operations
        assert_eq!(
            http_method_to_s3_action("HEAD", "/bucket1", "", true),
            "s3:ListBucket"
        );
        assert_eq!(
            http_method_to_s3_action("PUT", "/bucket1", "", true),
            "s3:CreateBucket"
        );
        assert_eq!(
            http_method_to_s3_action("DELETE", "/bucket1", "", true),
            "s3:DeleteBucket"
        );
        // GetBucketLocation
        assert_eq!(
            http_method_to_s3_action("GET", "/bucket1", "location", true),
            "s3:GetBucketLocation"
        );
    }

    #[tokio::test]
    async fn test_verify_sigv4_missing_auth_header_required() {
        let cred_store = Arc::new(RwLock::new(CredentialStore::new_empty()));
        let db_conn = crate::db::initialize_in_memory_database().await.unwrap();
        let db = Arc::new(DBService::new(Arc::new(db_conn)));

        // Create request without Authorization header
        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost:9000/bucket1/test.txt")
            .body(vec![])
            .unwrap();

        // Verify with signature required - should fail
        let result = verify_sigv4(request, cred_store, db, "crabcakes").await;

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
        let cred_store = Arc::new(RwLock::new(CredentialStore::new_empty()));
        let db_conn = crate::db::initialize_in_memory_database().await.unwrap();
        let db = Arc::new(DBService::new(Arc::new(db_conn)));

        // Create request without Authorization header
        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost:9000/bucket1/test.txt")
            .body(vec![])
            .unwrap();

        // Verify with signature not required - should return error indicating no auth
        let result = verify_sigv4(request, cred_store, db, "crabcakes").await;

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
        let cred_store = Arc::new(RwLock::new(CredentialStore::new_empty()));
        let db_conn = crate::db::initialize_in_memory_database().await.unwrap();
        let db = Arc::new(DBService::new(Arc::new(db_conn)));

        // Create request with malformed Authorization header
        let request = http::Request::builder()
            .method("GET")
            .uri("http://localhost:9000/bucket1/test.txt")
            .header(AUTHORIZATION, "Not a valid signature")
            .body(vec![])
            .unwrap();

        // Verify - should fail
        let result = verify_sigv4(request, cred_store, db, "crabcakes").await;

        assert!(
            result.is_err(),
            "Malformed auth header should fail verification"
        );
    }
}
