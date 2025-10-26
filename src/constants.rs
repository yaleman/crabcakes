use std::{
    fmt::{Display, Formatter},
    sync::LazyLock,
};

use chrono::Duration;
use enum_iterator::Sequence;
use serde::{Deserialize, Serialize};

/// This is the temporary access key length
pub(crate) static TEMP_ACCESS_KEY_LENGTH: usize = 20;
/// This is related to the AWS secret access key length
pub(crate) static SECRET_ACCESS_KEY_LENGTH: usize = 40;

/// The signature header value for AWS Signature Version 4
pub static AWS4_HMAC_SHA256: &str = "AWS4-HMAC-SHA256";

/// Header for AWS S3 requests that use chunked transfer encoding with signature v4
pub(crate) static X_AMZ_DECODED_CONTENT_LENGTH: &str = "x-amz-decoded-content-length";
/// Trailer header
pub(crate) static X_AMZ_TRAILER: &str = "x-amz-trailer";

/// How long a OAuth-provided temporary credential will live
pub(crate) static MAX_TEMP_CREDS_DURATION: LazyLock<Duration> =
    LazyLock::new(|| Duration::seconds(3600));

pub(crate) static S3: &str = "s3";

pub(crate) static DEFAULT_REGION: &str = "crabcakes";

pub(crate) static CSRF_TOKEN_LENGTH: usize = 32;

/// Mock AWS Account ID for generated principals
pub(crate) const MOCK_ACCOUNT_ID: &str = "000000000000";

/// Used for logging
pub(crate) static TRACE_STATUS_CODE: &str = "status_code";
pub(crate) static TRACE_S3_ACTION: &str = "s3_action";
pub(crate) static TRACE_METHOD: &str = "method";
pub(crate) static TRACE_URI: &str = "uri";
pub(crate) static TRACE_REMOTE_ADDR: &str = "remote_addr";
pub(crate) static TRACE_BUCKET: &str = "bucket";
pub(crate) static TRACE_KEY: &str = "key";
pub(crate) static TRACE_COPY_SOURCE: &str = "copy_source";
pub(crate) static TRACE_HAS_RANGE_HEADER: &str = "has_range_header";
pub(crate) static TRACE_USER: &str = "user";

pub(crate) static MULTIPART_PATH_PREFIX: &str = ".multipart";

/// Reserved bucket names that cannot be used as S3 buckets
/// These are reserved for the admin UI and API endpoints
pub(crate) static RESERVED_BUCKET_NAMES: &[&str] = &[
    MULTIPART_PATH_PREFIX,
    "admin",
    "api",
    "login",
    "logout",
    "oauth2",
    ".well-known",
    "config",
    "oidc",
    "crabcakes",
    "docs",
    "help",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Sequence, Deserialize)]
pub enum S3Action {
    #[serde(alias = "s3:*")]
    Wildcard,
    #[serde(alias = "s3:GetObject")]
    GetObject,
    #[serde(alias = "s3:PutObject")]
    PutObject,
    #[serde(alias = "s3:DeleteObject")]
    DeleteObject,
    #[serde(alias = "s3:ListBucket")]
    ListBucket,
    #[serde(alias = "s3:AbortMultipartUpload")]
    AbortMultipartUpload,
    #[serde(alias = "s3:CreateBucket")]
    CreateBucket,
    #[serde(alias = "s3:DeleteBucket")]
    DeleteBucket,
    #[serde(alias = "s3:ListBucketMultipartUploads")]
    ListBucketMultipartUploads,
    #[serde(alias = "s3:ListMultipartUploadParts")]
    ListMultipartUploadParts,
    #[serde(alias = "s3:GetObjectTagging")]
    GetObjectTagging,
    #[serde(alias = "s3:PutObjectTagging")]
    PutObjectTagging,

    #[serde(alias = "s3:DeleteObjectTagging")]
    DeleteObjectTagging,
    #[serde(alias = "s3:GetObjectAttributes")]
    GetObjectAttributes,
    #[serde(alias = "s3:GetBucketLocation")]
    GetBucketLocation,
    #[serde(alias = "s3:ListAllMyBuckets")]
    ListAllMyBuckets,
    #[serde(alias = "s3:GetBucketWebsite")]
    GetBucketWebsite,
    #[serde(alias = "s3:PutBucketWebsite")]
    PutBucketWebsite,
    #[serde(alias = "s3:DeleteBucketWebsite")]
    DeleteBucketWebsite,
}

impl S3Action {
    pub(crate) fn all_as_str() -> Vec<String> {
        enum_iterator::all::<S3Action>()
            .map(|action| action.to_string())
            .collect()
    }
}

impl AsRef<str> for S3Action {
    fn as_ref(&self) -> &'static str {
        match self {
            S3Action::Wildcard => "s3:*",
            S3Action::GetObject => "s3:GetObject",
            S3Action::PutObject => "s3:PutObject",
            S3Action::DeleteObject => "s3:DeleteObject",
            S3Action::ListBucket => "s3:ListBucket",
            S3Action::AbortMultipartUpload => "s3:AbortMultipartUpload",
            S3Action::CreateBucket => "s3:CreateBucket",
            S3Action::DeleteBucket => "s3:DeleteBucket",
            S3Action::ListBucketMultipartUploads => "s3:ListBucketMultipartUploads",
            S3Action::ListMultipartUploadParts => "s3:ListMultipartUploadParts",
            S3Action::GetObjectTagging => "s3:GetObjectTagging",
            S3Action::PutObjectTagging => "s3:PutObjectTagging",
            S3Action::DeleteObjectTagging => "s3:DeleteObjectTagging",
            S3Action::GetObjectAttributes => "s3:GetObjectAttributes",
            S3Action::GetBucketLocation => "s3:GetBucketLocation",
            S3Action::ListAllMyBuckets => "s3:ListAllMyBuckets",
            S3Action::GetBucketWebsite => "s3:GetBucketWebsite",
            S3Action::PutBucketWebsite => "s3:PutBucketWebsite",
            S3Action::DeleteBucketWebsite => "s3:DeleteBucketWebsite",
        }
    }
}

impl Display for S3Action {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl From<S3Action> for String {
    fn from(value: S3Action) -> Self {
        value.to_string()
    }
}

pub(crate) enum SessionKey {
    CsrfToken,
    UserEmail,
    UserId,
    AccessKeyId,
}

impl AsRef<str> for SessionKey {
    fn as_ref(&self) -> &'static str {
        match self {
            SessionKey::CsrfToken => "csrf_token",
            SessionKey::UserEmail => "user_email",
            SessionKey::UserId => "user_id",
            SessionKey::AccessKeyId => "access_key_id",
        }
    }
}

#[cfg(test)]
pub(crate) static TEST_ALLOWED_BUCKET: &str = "bucket1";
#[cfg(test)]
pub(crate) static TEST_ALLOWED_BUCKET2: &str = "bucket2";

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum WebPage {
    Buckets,
    Identities,
    Policies,
    System,
    Profile,
    PolicyTroubleshooter,
}

impl AsRef<str> for WebPage {
    fn as_ref(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Profile => "profile",
            Self::Buckets => "buckets",
            Self::Identities => "identities",
            Self::Policies => "policies",
            Self::PolicyTroubleshooter => "policy_troubleshooter",
        }
    }
}

impl Display for WebPage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_ref())
    }
}

#[derive(Copy, Clone, Deserialize, Serialize)]
#[serde(rename = "lowercase")]
pub(crate) enum PolicyAction {
    Create,
    Edit,
}

impl PolicyAction {
    pub(crate) fn is_edit(self) -> bool {
        matches!(self, PolicyAction::Edit)
    }
}

impl AsRef<str> for PolicyAction {
    fn as_ref(&self) -> &'static str {
        match self {
            PolicyAction::Create => "create",
            PolicyAction::Edit => "edit",
        }
    }
}
