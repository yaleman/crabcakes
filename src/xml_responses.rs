use chrono::Utc;
use quick_xml::se::to_string;
use serde::Serialize;

use crate::filesystem::DirectoryEntry;

#[derive(Serialize)]
#[serde(rename = "ListBucketResult")]
pub struct ListBucketResponse {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Prefix")]
    pub prefix: String,
    #[serde(rename = "MaxKeys")]
    pub max_keys: usize,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "Contents")]
    pub contents: Vec<S3Object>,
    #[serde(
        rename = "NextContinuationToken",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_continuation_token: Option<String>,
}

#[derive(Serialize)]
pub struct S3Object {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "Size")]
    pub size: u64,
    #[serde(rename = "StorageClass")]
    pub storage_class: String,
}

#[derive(Serialize)]
#[serde(rename = "ListAllMyBucketsResult")]
pub struct ListBucketsResponse {
    #[serde(rename = "Owner")]
    pub owner: Owner,
    #[serde(rename = "Buckets")]
    pub buckets: Buckets,
}

#[derive(Serialize)]
pub struct Owner {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "DisplayName")]
    pub display_name: String,
}

#[derive(Serialize)]
pub struct Buckets {
    #[serde(rename = "Bucket")]
    pub bucket: Vec<Bucket>,
}

#[derive(Serialize)]
pub struct Bucket {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "CreationDate")]
    pub creation_date: String,
}

impl ListBucketResponse {
    pub fn new(
        bucket_name: String,
        prefix: String,
        max_keys: usize,
        entries: Vec<DirectoryEntry>,
        next_continuation_token: Option<String>,
    ) -> Self {
        let contents = entries
            .into_iter()
            .map(|entry| S3Object {
                key: entry.key,
                last_modified: entry
                    .last_modified
                    .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                    .to_string(),
                etag: entry.etag,
                size: entry.size,
                storage_class: "STANDARD".to_string(),
            })
            .collect();

        let is_truncated = next_continuation_token.is_some();

        Self {
            name: bucket_name,
            prefix,
            max_keys,
            is_truncated,
            contents,
            next_continuation_token,
        }
    }

    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str(&to_string(self).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?);
        Ok(xml)
    }
}

impl ListBucketsResponse {
    pub fn from_buckets(bucket_names: Vec<String>) -> Self {
        let now = Utc::now();
        let creation_date = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let buckets = bucket_names
            .into_iter()
            .map(|name| Bucket {
                name,
                creation_date: creation_date.clone(),
            })
            .collect();

        Self {
            owner: Owner {
                id: "crabcakes-owner".to_string(),
                display_name: "Crabcakes".to_string(),
            },
            buckets: Buckets { bucket: buckets },
        }
    }

    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str(&to_string(self).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?);
        Ok(xml)
    }
}
