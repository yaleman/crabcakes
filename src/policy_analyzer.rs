//! Policy analysis utilities for extracting identity and permission information
//!
//! This module provides functionality to analyze IAM policies and extract
//! information about principals (identities) and their permissions.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use iam_rs::{IAMPolicy, Principal, PrincipalId};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::constants::MOCK_ACCOUNT_ID;

/// Type of identity principal
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum IdentityType {
    User,
    Role,
    Service,
    Wildcard,
    Other,
}

impl std::fmt::Display for IdentityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityType::User => write!(f, "User"),
            IdentityType::Role => write!(f, "Role"),
            IdentityType::Service => write!(f, "Service"),
            IdentityType::Wildcard => write!(f, "Wildcard"),
            IdentityType::Other => write!(f, "Other"),
        }
    }
}

/// Information about a principal's permissions from a specific policy
#[derive(Debug, Clone, Serialize)]
pub struct PolicyPermission {
    pub policy_name: String,
    pub effect: String, // "Allow" or "Deny"
    pub actions: Vec<String>,
    pub resources: Vec<String>,
}

/// Complete information about an identity across all policies
#[derive(Debug, Clone, Serialize)]
pub struct IdentityInfo {
    pub principal_arn: String,
    pub display_name: String,
    pub identity_type: IdentityType,
    pub policies: Vec<PolicyPermission>,
}

impl IdentityInfo {
    /// Get a summary count of unique actions across all policies
    pub fn action_count(&self) -> usize {
        let mut actions = HashSet::new();
        for policy in &self.policies {
            for action in &policy.actions {
                actions.insert(action.clone());
            }
        }
        actions.len()
    }

    /// Get a summary count of unique resources across all policies
    pub fn resource_count(&self) -> usize {
        let mut resources = HashSet::new();
        for policy in &self.policies {
            for resource in &policy.resources {
                resources.insert(resource.clone());
            }
        }
        resources.len()
    }
}

/// Extract display name from a principal ARN
/// Examples:
/// - "arn:aws:iam:::user/alice" -> "alice"
/// - "arn:aws:iam:::role/admin" -> "admin"
/// - "*" -> "All Identities (Wildcard)"
pub fn extract_display_name(principal_arn: &str) -> String {
    if principal_arn == "*" {
        return "All Identities (Wildcard)".to_string();
    }

    // Try to extract the name after the last '/'
    if let Some(last_slash) = principal_arn.rfind('/') {
        let name = &principal_arn[last_slash + 1..];
        if !name.is_empty() {
            return name.to_string();
        }
    }

    // Fallback to the full ARN if we can't extract a name
    principal_arn.to_string()
}

/// Determine identity type from principal ARN
pub(crate) fn determine_identity_type(principal_arn: &str) -> IdentityType {
    if principal_arn == "*" {
        return IdentityType::Wildcard;
    }

    if principal_arn.contains(":user/") {
        IdentityType::User
    } else if principal_arn.contains(":role/") {
        IdentityType::Role
    } else if principal_arn.contains(".amazonaws.com") {
        IdentityType::Service
    } else {
        IdentityType::Other
    }
}

/// Convert a Principal enum to a list of principal ARN strings
fn principal_to_arns(principal: &Principal) -> Vec<String> {
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
}

fn normalize_admin_principal(principal_arn: &str) -> String {
    principal_arn.replace(
        &format!("arn:aws:iam::{MOCK_ACCOUNT_ID}:"),
        "arn:aws:iam:::",
    )
}

fn admin_principals_match(candidate: &str, requested: &str) -> bool {
    normalize_admin_principal(candidate) == normalize_admin_principal(requested)
}

/// Extract all unique principals from a set of policies
pub async fn extract_principals(policies: Arc<RwLock<HashMap<String, IAMPolicy>>>) -> Vec<String> {
    let mut principals = HashSet::new();

    for policy in policies.read().await.values() {
        for statement in &policy.statement {
            // Add principals from Principal field
            if let Some(ref principal) = statement.principal {
                for arn in principal_to_arns(principal) {
                    principals.insert(arn);
                }
            }

            // Add principals from NotPrincipal field
            if let Some(ref not_principal) = statement.not_principal {
                for arn in principal_to_arns(not_principal) {
                    principals.insert(arn);
                }
            }
        }
    }

    let mut result: Vec<String> = principals.into_iter().collect();
    result.sort();
    result
}

/// Get all permissions for a specific principal across all policies
pub async fn get_identity_permissions(
    principal_arn: &str,
    policies: Arc<RwLock<HashMap<String, IAMPolicy>>>,
) -> IdentityInfo {
    let mut policy_permissions = Vec::new();

    for (policy_name, policy) in policies.read().await.iter() {
        for statement in &policy.statement {
            // Check if this statement applies to the given principal
            let applies = if let Some(ref principal) = statement.principal {
                principal_to_arns(principal)
                    .iter()
                    .any(|arn| admin_principals_match(arn, principal_arn))
            } else {
                false
            };

            if !applies {
                continue;
            }

            // Extract actions
            let actions = if let Some(ref action) = statement.action {
                use iam_rs::IAMAction;
                match action {
                    IAMAction::Single(s) => vec![s.clone()],
                    IAMAction::Multiple(v) => v.clone(),
                }
            } else {
                vec![]
            };

            // Extract resources
            let resources = if let Some(ref resource) = statement.resource {
                use iam_rs::IAMResource;
                match resource {
                    IAMResource::Single(s) => vec![s.to_string()],
                    IAMResource::Multiple(v) => v.iter().map(|r| r.to_string()).collect(),
                }
            } else {
                vec![]
            };

            policy_permissions.push(PolicyPermission {
                policy_name: policy_name.clone(),
                effect: format!("{:?}", statement.effect),
                actions,
                resources,
            });
        }
    }

    IdentityInfo {
        principal_arn: principal_arn.to_string(),
        display_name: extract_display_name(principal_arn),
        identity_type: determine_identity_type(principal_arn),
        policies: policy_permissions,
    }
}

/// Get all identities with their permissions
pub async fn get_all_identities(
    policies: Arc<RwLock<HashMap<String, IAMPolicy>>>,
) -> Vec<IdentityInfo> {
    let principal_arns = extract_principals(policies.clone()).await;

    let mut res: Vec<IdentityInfo> = Vec::new();

    for arn in principal_arns {
        res.push(get_identity_permissions(&arn, policies.clone()).await);
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_display_name() {
        assert_eq!(
            extract_display_name("arn:aws:iam:::user/alice"),
            "alice".to_string()
        );
        assert_eq!(
            extract_display_name("arn:aws:iam:::role/admin"),
            "admin".to_string()
        );
        assert_eq!(extract_display_name("*"), "All Identities (Wildcard)");
    }

    #[test]
    fn test_determine_identity_type() {
        assert_eq!(
            determine_identity_type("arn:aws:iam:::user/alice"),
            IdentityType::User
        );
        assert_eq!(
            determine_identity_type("arn:aws:iam:::role/admin"),
            IdentityType::Role
        );
        assert_eq!(determine_identity_type("*"), IdentityType::Wildcard);
        assert_eq!(
            determine_identity_type("s3.amazonaws.com"),
            IdentityType::Service
        );
    }

    #[test]
    fn test_admin_principals_match_mock_account_id() {
        assert!(admin_principals_match(
            "arn:aws:iam::000000000000:user/images",
            "arn:aws:iam:::user/images"
        ));
        assert!(admin_principals_match(
            "arn:aws:iam:::user/images",
            "arn:aws:iam:::user/images"
        ));
        assert!(!admin_principals_match(
            "arn:aws:iam::000000000000:user/images",
            "arn:aws:iam:::user/not-images"
        ));
    }

    #[tokio::test]
    async fn test_get_identity_permissions_matches_mock_account_id_policy() {
        let policy: IAMPolicy = serde_json::from_value(serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::000000000000:user/images"
                },
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::images/*"
            }]
        }))
        .expect("test policy should parse");
        let policies = Arc::new(RwLock::new(HashMap::from([(
            "images-policy".to_string(),
            policy,
        )])));

        let identity =
            get_identity_permissions("arn:aws:iam:::user/images", policies.clone()).await;
        assert_eq!(identity.policies.len(), 1);
        assert_eq!(identity.policies[0].policy_name, "images-policy");

        let unrelated = get_identity_permissions("arn:aws:iam:::user/not-images", policies).await;
        assert!(unrelated.policies.is_empty());
    }
}
