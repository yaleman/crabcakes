use super::serde::*;
use crate::constants::{PolicyAction, S3Action, WebPage};
use crate::web::serde::PolicyInfo;

use askama::Template;

/// Error page template
#[derive(Template)]
#[template(path = "error.html")]
pub(crate) struct ErrorTemplate {
    pub(crate) error_message: String,
}

/// Profile page template
#[derive(Template)]
#[template(path = "profile.html")]
pub(crate) struct ProfileTemplate {
    pub(crate) page: &'static str,
    pub(crate) user_email: String,
    pub(crate) user_id: String,
    pub(crate) access_key_id: String,
    pub(crate) secret_key_preview: String,
    pub(crate) expires_at: String,
}

/// System page template
#[derive(Template)]
#[template(path = "system.html")]
pub(crate) struct SystemTemplate {
    pub(crate) page: &'static str,
}

/// Policies list template
#[derive(Template)]
#[template(path = "policies.html")]
pub(crate) struct PoliciesTemplate {
    pub(crate) page: &'static str,
    pub(crate) policies: Vec<PolicyInfo>,
}

/// Policy detail template
#[derive(Template)]
#[template(path = "policy_detail.html")]
pub(crate) struct PolicyDetailTemplate {
    pub(crate) page: &'static str,
    pub(crate) policy_name: String,
    pub(crate) policy_json: String,
    pub(crate) policy_principal_permissions: Vec<PolicyPrincipalPermission>,
}

/// Policy form template (for creating/editing)
#[derive(Template)]
#[template(path = "policy_form.html")]
pub(crate) struct PolicyFormTemplate {
    pub(crate) page: &'static str,
    pub(crate) action: PolicyAction,
    pub(crate) policy_name: String,
    pub(crate) policy_json: String,
}

/// Credential form template (for creating/editing)
#[derive(Template)]
#[template(path = "credential_form.html")]
pub(crate) struct CredentialFormTemplate {
    pub(crate) page: &'static str,
    pub(crate) access_key_id: String,
    pub(crate) is_edit: bool,
}

impl Default for CredentialFormTemplate {
    fn default() -> Self {
        Self {
            page: WebPage::Identities.as_ref(),
            access_key_id: String::new(),
            is_edit: false,
        }
    }
}

/// Buckets list template
#[derive(Template)]
#[template(path = "buckets.html")]
pub(crate) struct BucketsTemplate {
    pub(crate) page: &'static str,
    pub(crate) buckets: Vec<BucketInfo>,
}

impl Default for BucketsTemplate {
    fn default() -> Self {
        Self {
            page: WebPage::Buckets.as_ref(),
            buckets: Vec::new(),
        }
    }
}

/// Bucket form template (for creating buckets)
#[derive(Template)]
#[template(path = "bucket_form.html")]
pub(crate) struct BucketFormTemplate {
    pub(crate) page: &'static str,
}

/// Bucket delete confirmation template
#[derive(Template)]
#[template(path = "bucket_delete.html")]
pub(crate) struct BucketDeleteTemplate {
    pub(crate) page: &'static str,
    pub(crate) bucket_name: String,
    pub(crate) object_count: usize,
}

/// Bucket detail template
#[derive(Template)]
#[template(path = "bucket_detail.html")]
pub(crate) struct BucketDetailTemplate {
    pub(crate) page: &'static str,
    pub(crate) bucket_name: String,
    pub(crate) objects: Vec<ObjectInfo>,
    pub(crate) website_enabled: bool,
}

/// Bucket settings template
#[derive(Template)]
#[template(path = "bucket_settings.html")]
pub(crate) struct BucketSettingsTemplate {
    pub(crate) page: &'static str,
    pub(crate) bucket_name: String,
}

/// Identities list template
#[derive(Template)]
#[template(path = "identities.html")]
pub(crate) struct IdentitiesTemplate {
    pub(crate) page: &'static str,
    pub(crate) identities: Vec<IdentitySummary>,
    pub(crate) temporary_credentials: Vec<TemporaryCredentialSummary>,
}

/// Identity detail template
#[derive(Template)]
#[template(path = "identity_detail.html")]
pub(crate) struct IdentityDetailTemplate {
    pub(crate) page: &'static str,
    pub(crate) identity: crate::policy_analyzer::IdentityInfo,
    pub(crate) has_credential: bool,
}

/// Identity detail template
#[derive(Template)]
#[template(path = "troubleshooter.html")]
pub(crate) struct PolicyTroubleshooterTemplate {
    pub(crate) page: &'static str,
    pub(crate) bucket: String,
    pub(crate) key: String,
    pub(crate) user: String,
    pub(crate) action: String,
    pub(crate) policy_name: String,
    pub(crate) policy_names: Vec<String>,
    pub(crate) s3_actions: Vec<String>,
}

impl Default for PolicyTroubleshooterTemplate {
    fn default() -> Self {
        Self {
            page: WebPage::PolicyTroubleshooter.as_ref(),
            s3_actions: S3Action::all_as_str(),
            bucket: Default::default(),
            key: Default::default(),
            user: Default::default(),
            action: Default::default(),
            policy_name: Default::default(),
            policy_names: Default::default(),
        }
    }
}
