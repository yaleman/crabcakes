use hyper::Request;
use iam_rs::{Arn, Context, ContextValue, IAMRequest, Principal, PrincipalId};
use tracing::debug;

/// Extract authentication context from HTTP request
pub struct AuthContext {
    pub principal: Principal,
    pub username: Option<String>,
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
            let arn = format!("arn:aws:iam::123456789012:user/{}", username);
            return Self {
                principal: Principal::Aws(PrincipalId::String(arn)),
                username: Some(username.to_string()),
            };
        }

        // Check Authorization header for AWS credentials
        if let Some(auth_header) = req.headers().get("authorization")
            && let Ok(auth_str) = auth_header.to_str()
        {
            // Basic parsing of AWS Signature V4 format
            // Format: AWS4-HMAC-SHA256 Credential=ACCESS_KEY/date/region/service/aws4_request
            if let Some(username) = Self::parse_access_key(auth_str) {
                debug!(username = %username, "Authenticated user from Authorization header");
                let arn = format!("arn:aws:iam::123456789012:user/{}", username);
                return Self {
                    principal: Principal::Aws(PrincipalId::String(arn)),
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
pub fn http_method_to_s3_action(method: &str, path: &str, query: &str) -> &'static str {
    match method {
        "GET" if query.contains("list-type=2") => "s3:ListBucket",
        "GET" if path == "/" => "s3:ListAllMyBuckets",
        "GET" => "s3:GetObject",
        "HEAD" => "s3:GetObject", // HeadObject uses GetObject permission
        "PUT" => "s3:PutObject",
        "DELETE" => "s3:DeleteObject",
        "POST" if query.contains("delete") => "s3:DeleteObject",
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
        let auth = "AWS4-HMAC-SHA256 Credential=alice/20231201/us-east-1/s3/aws4_request";
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
            http_method_to_s3_action("GET", "/", ""),
            "s3:ListAllMyBuckets"
        );
        assert_eq!(
            http_method_to_s3_action("GET", "/bucket1", "list-type=2"),
            "s3:ListBucket"
        );
        assert_eq!(
            http_method_to_s3_action("GET", "/bucket1/test.txt", ""),
            "s3:GetObject"
        );
        assert_eq!(
            http_method_to_s3_action("HEAD", "/bucket1/test.txt", ""),
            "s3:GetObject"
        );
        assert_eq!(
            http_method_to_s3_action("PUT", "/bucket1/test.txt", ""),
            "s3:PutObject"
        );
    }
}
