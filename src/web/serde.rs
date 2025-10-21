use iam_rs::EvaluationResult;
use serde::{Deserialize, Serialize};

/// Principal permission entry for policy detail page (one row per principal+action+resource)
#[derive(Debug, Serialize, PartialEq, Eq, Hash)]
pub(crate) struct PolicyPrincipalPermission {
    pub(crate) arn: String,
    pub(crate) display_name: String,
    pub(crate) identity_type: String,
    pub(crate) effect: String,
    pub(crate) action: String,
    pub(crate) resource: String,
}

/// Temporary credential summary for listing
#[derive(Debug)]
pub(crate) struct TemporaryCredentialSummary {
    pub(crate) access_key_id: String,
    pub(crate) user_email: String,
    pub(crate) user_id: String,
    pub(crate) expires_at: String,
    pub(crate) created_at: String,
}

/// Policy info for listing
#[derive(Debug)]
pub(crate) struct PolicyInfo {
    pub(crate) name: String,
    pub(crate) statement_count: usize,
}

/// Identity summary for listing
#[derive(Debug)]
pub(crate) struct IdentitySummary {
    pub(crate) principal_arn: String,
    pub(crate) display_name: String,
    pub(crate) identity_type: String,
    pub(crate) policy_count: usize,
    pub(crate) action_count: usize,
    pub(crate) has_credential: bool,
}

/// Object info for bucket listing
#[derive(Debug)]
pub(crate) struct ObjectInfo {
    pub(crate) key: String,
    pub(crate) size_formatted: String,
    pub(crate) last_modified: String,
}

/// Bucket info for listing
#[derive(Debug)]
pub(crate) struct BucketInfo {
    pub(crate) name: String,
    pub(crate) website_enabled: bool,
}

#[derive(Deserialize, Debug)]
pub(crate) struct TroubleShooterForm {
    pub(crate) bucket: String,
    pub(crate) key: String,
    pub(crate) user: String,
    pub(crate) action: String,
    pub(crate) policy: String,
}

#[derive(Serialize, Debug)]
pub(crate) struct TroubleShooterResponse {
    pub(crate) decision: EvaluationResult,
}

// API response types for RequestHandler methods

/// Policy info for API listing (includes full policy JSON)
#[derive(Serialize, Debug)]
pub(crate) struct ApiPolicyInfo {
    pub(crate) name: String,
    pub(crate) policy: serde_json::Value,
}

/// Credential info for API listing (without secret)
#[derive(Serialize, Debug)]
pub(crate) struct CredentialInfo {
    pub(crate) access_key_id: String,
    // DO NOT include secret_access_key
}

/// Database vacuum statistics
#[derive(Serialize, Debug)]
pub(crate) struct VacuumStats {
    pub(crate) page_count: i64,
    pub(crate) page_size: i64,
    pub(crate) freelist_count: i64,
    pub(crate) total_size_bytes: i64,
    pub(crate) freelist_size_bytes: i64,
}

/// Database vacuum execution result
#[derive(Serialize, Debug)]
pub(crate) struct VacuumResult {
    pub(crate) success: bool,
    pub(crate) pages_freed: i64,
}

// Parse request body
#[derive(serde::Deserialize)]
pub(crate) struct PolicyRequest {
    pub(crate) name: String,
    pub(crate) policy: iam_rs::IAMPolicy,
}
