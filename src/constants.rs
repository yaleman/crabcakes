use std::{
    fmt::{Display, Formatter},
    sync::LazyLock,
};

use chrono::Duration;
use enum_iterator::Sequence;
use serde::Deserialize;

/// How long a OAuth-provided temporary credential will live
pub(crate) static MAX_TEMP_CREDS_DURATION: LazyLock<Duration> =
    LazyLock::new(|| Duration::seconds(3600));

/// Reserved bucket names that cannot be used as S3 buckets
/// These are reserved for the admin UI and API endpoints
pub(crate) static RESERVED_BUCKET_NAMES: &[&str] = &[
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
