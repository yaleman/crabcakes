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
