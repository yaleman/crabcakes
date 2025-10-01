use std::str::FromStr;
use std::sync::Arc;

use hyper::{Request, header::AUTHORIZATION};
use iam_rs::{Arn, Context, ContextValue, IAMRequest, Principal, PrincipalId};
use scratchstack_aws_principal;
use scratchstack_aws_signature::{
    GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, NO_ADDITIONAL_SIGNED_HEADERS,
    SignatureOptions, service_for_signing_key_fn, sigv4_validate_request,
};
use tower::BoxError;
use tracing::{debug, warn};

use crate::credentials::CredentialStore;
use crate::error::CrabCakesError;

/// Mock AWS Account ID for generated principals
const MOCK_ACCOUNT_ID: &str = "000000000000";

/// Extract authentication context from HTTP request
pub struct AuthContext {
    pub principal: Principal,
    pub username: Option<String>,
}

/// Verification result for AWS SigV4 signature
pub struct VerifiedRequest {
    pub access_key_id: String,
    pub principal: scratchstack_aws_principal::Principal,
}

/// Verify AWS Signature V4 for a request
pub async fn verify_sigv4(
    req: http::Request<Vec<u8>>,
    credentials_store: Arc<CredentialStore>,
    region: &str,
    require_signature: bool,
) -> Result<VerifiedRequest, CrabCakesError> {
    // Check if Authorization header exists
    let has_auth = req.headers().get(AUTHORIZATION).is_some();

    if !has_auth && !require_signature {
        // Allow anonymous requests if signature not required
        warn!("No authorization header found, but signature not required - allowing anonymous");
        // TODO: be more explicit about this
        return Err(CrabCakesError::NoAuthenticationSupplied(
            "No authorization header".to_string(),
        ));
    } else if !has_auth {
        return Err(CrabCakesError::NoAuthenticationSupplied(
            "Missing authorization header".to_string(),
        ));
    }

    // Create a closure that will fetch signing keys
    let get_signing_key = {
        let cred_store = credentials_store.clone();
        move |request: GetSigningKeyRequest| {
            let cred_store = cred_store.clone();
            async move {
                let access_key = request.access_key().to_string();
                debug!(access_key = %access_key, "Looking up signing key");

                // Get the credential from the store
                let secret_access_key = cred_store
                    .get_credential(&access_key)
                    .ok_or(CrabCakesError::InvalidCredential)?;

                // Convert secret key to KSecretKey
                let secret_key = KSecretKey::from_str(secret_access_key).map_err(|err| {
                    debug!(
                        access_key_id = access_key,
                        "Failed to parse secret key: {}", err
                    );
                    CrabCakesError::InvalidCredential
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

                Ok(GetSigningKeyResponse::builder()
                    .principal(principal)
                    .signing_key(signing_key)
                    .build()?)
            }
        }
    };

    // Wrap the closure in a tower::Service
    let mut service = service_for_signing_key_fn(get_signing_key);

    // S3-specific signature options
    let signature_options = SignatureOptions::url_encode_form();

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
    .map_err(|e| CrabCakesError::other(format!("Signature verification failed: {}", e)))?;

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
        .ok_or_else(|| CrabCakesError::other("No user identity found in principal"))?;

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
        // Special cases
        ("GET", _, q, _) if q.contains("list-type=2") => "s3:ListBucket",
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
    }
}
