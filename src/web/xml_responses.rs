//! AWS S3-compatible XML response serialization.
//!
//! Defines response structures and XML serialization for S3 API operations.

use chrono::Utc;
use quick_xml::se::to_string;
use serde::{Deserialize, Serialize};

use crate::filesystem::DirectoryEntry;

pub(crate) fn to_xml<T>(input: T) -> Result<String, Box<dyn std::error::Error>>
where
    T: Serialize,
{
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&to_string(&input).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?);
    Ok(xml)
}

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
pub struct ListAllMyBucketsResult {
    #[serde(rename = "Owner")]
    pub owner: Owner,
    #[serde(rename = "Buckets")]
    pub buckets: Buckets,
}

#[derive(Serialize)]
pub struct Owner {
    #[serde(rename = "ID")]
    pub id: String,
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
}

impl ListAllMyBucketsResult {
    pub fn from_buckets(bucket_names: Vec<String>) -> Self {
        let now = Utc::now();
        // TODO: this should really be the actual bucket creation date from the filesystem
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
                id: "crabcakes".to_string(),
            },
            buckets: Buckets { bucket: buckets },
        }
    }
}

// DeleteObjects request/response structures
#[derive(Deserialize)]
#[serde(rename = "Delete")]
pub struct DeleteRequest {
    #[serde(rename = "Object")]
    pub objects: Vec<DeleteObject>,
    #[serde(rename = "Quiet", default)]
    pub quiet: bool,
}

#[derive(Deserialize)]
pub struct DeleteObject {
    #[serde(rename = "Key")]
    pub key: String,
}

#[derive(Serialize)]
#[serde(rename = "DeleteResult")]
pub struct DeleteResponse {
    #[serde(rename = "Deleted", skip_serializing_if = "Vec::is_empty")]
    pub deleted: Vec<DeletedObject>,
    #[serde(rename = "Error", skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<DeleteError>,
}

#[derive(Serialize)]
pub struct DeletedObject {
    #[serde(rename = "Key")]
    pub key: String,
}

#[derive(Serialize)]
pub struct DeleteError {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
}

// CopyObject response structure
#[derive(Serialize)]
#[serde(rename = "CopyObjectResult")]
pub struct CopyObjectResponse {
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
}

// UploadPartCopy response structure (same fields as CopyObjectResponse but different root element)
#[derive(Serialize)]
#[serde(rename = "CopyPartResult")]
pub struct CopyPartResponse {
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
}

// GetBucketLocation response structure
#[derive(Serialize)]
#[serde(rename = "LocationConstraint")]
pub struct GetBucketLocationResponse {
    #[serde(rename = "$value")]
    pub location: String,
}

// ListObjectsV1 response structure (legacy API)
#[derive(Serialize)]
#[serde(rename = "ListBucketResult")]
pub struct ListBucketV1Response {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Prefix")]
    pub prefix: String,
    #[serde(rename = "Marker")]
    pub marker: String,
    #[serde(rename = "MaxKeys")]
    pub max_keys: usize,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "Contents")]
    pub contents: Vec<S3Object>,
    #[serde(rename = "NextMarker", skip_serializing_if = "Option::is_none")]
    pub next_marker: Option<String>,
}

impl ListBucketV1Response {
    pub fn new(
        bucket_name: String,
        prefix: String,
        marker: String,
        max_keys: usize,
        entries: Vec<DirectoryEntry>,
        next_marker: Option<String>,
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

        let is_truncated = next_marker.is_some();

        Self {
            name: bucket_name,
            prefix,
            marker,
            max_keys,
            is_truncated,
            contents,
            next_marker,
        }
    }
}

// Multipart upload response structures

#[derive(Serialize)]
#[serde(rename = "InitiateMultipartUploadResult")]
pub struct InitiateMultipartUploadResponse {
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
}

#[derive(Serialize)]
#[serde(rename = "ListPartsResult")]
pub struct ListPartsResponse {
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
    #[serde(rename = "Part")]
    pub parts: Vec<PartItem>,
}

#[derive(Serialize)]
pub struct PartItem {
    #[serde(rename = "PartNumber")]
    pub part_number: u32,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "Size")]
    pub size: u64,
}

#[derive(Serialize)]
#[serde(rename = "ListMultipartUploadsResult")]
pub struct ListMultipartUploadsResponse {
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Upload")]
    pub uploads: Vec<MultipartUploadItem>,
}

#[derive(Serialize)]
pub struct MultipartUploadItem {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
    #[serde(rename = "Initiated")]
    pub initiated: String,
}

#[derive(Deserialize)]
#[serde(rename = "CompleteMultipartUpload")]
pub struct CompleteMultipartUploadRequest {
    #[serde(rename = "Part")]
    pub parts: Vec<CompletePart>,
}

#[derive(Deserialize)]
pub struct CompletePart {
    #[serde(rename = "PartNumber")]
    pub part_number: u32,
    #[serde(rename = "ETag")]
    pub etag: String,
}

#[derive(Serialize)]
#[serde(rename = "CompleteMultipartUploadResult")]
pub struct CompleteMultipartUploadResponse {
    #[serde(rename = "Location")]
    pub location: String,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "ETag")]
    pub etag: String,
}

// ===== Object Tagging Structures =====

#[derive(Deserialize)]
#[serde(rename = "Tagging")]
pub struct TaggingRequest {
    #[serde(rename = "TagSet")]
    pub tag_set: TagSet,
}

#[derive(Serialize, Deserialize)]
pub struct TagSet {
    #[serde(rename = "Tag", default)]
    pub tags: Vec<Tag>,
}

#[derive(Serialize, Deserialize)]
pub struct Tag {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Value")]
    pub value: String,
}

#[derive(Serialize)]
#[serde(rename = "Tagging")]
pub struct GetObjectTaggingResponse {
    #[serde(rename = "TagSet")]
    pub tag_set: TagSet,
}

#[derive(Serialize)]
#[serde(rename = "GetObjectAttributesOutput")]
pub struct GetObjectAttributesResponse {
    #[serde(rename = "ETag", skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(rename = "LastModified", skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    #[serde(rename = "ObjectSize", skip_serializing_if = "Option::is_none")]
    pub object_size: Option<u64>,
}

// ===== Bucket Website Configuration Structures =====

#[derive(Deserialize, Serialize)]
#[serde(rename = "WebsiteConfiguration")]
pub struct WebsiteConfiguration {
    #[serde(rename = "IndexDocument", skip_serializing_if = "Option::is_none")]
    pub index_document: Option<IndexDocument>,
    #[serde(rename = "ErrorDocument", skip_serializing_if = "Option::is_none")]
    pub error_document: Option<ErrorDocument>,
}

#[derive(Deserialize, Serialize)]
pub struct IndexDocument {
    #[serde(rename = "Suffix")]
    pub suffix: String,
}

#[derive(Deserialize, Serialize)]
pub struct ErrorDocument {
    #[serde(rename = "Key")]
    pub key: String,
}
