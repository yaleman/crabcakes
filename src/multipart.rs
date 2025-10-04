//! Multipart upload state management.
//!
//! Manages multipart upload sessions using filesystem-based storage for persistence.
//! Structure: `{root}/.multipart/{bucket}/{uploadId}/`
//! - `metadata.json` - Upload metadata (bucket, key, initiated time)
//! - `part-{partNumber}` - Individual uploaded parts

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::error::CrabCakesError;

/// Metadata for a multipart upload session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipartUploadMetadata {
    pub upload_id: String,
    pub bucket: String,
    pub key: String,
    pub initiated: DateTime<Utc>,
}

/// Information about an uploaded part
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartInfo {
    pub part_number: u32,
    pub etag: String,
    pub size: u64,
    pub last_modified: DateTime<Utc>,
}

/// Manages multipart upload state on the filesystem
pub struct MultipartManager {
    root_dir: PathBuf,
}

impl MultipartManager {
    /// Create a new MultipartManager
    pub fn new(root_dir: impl AsRef<Path>) -> Self {
        Self {
            root_dir: root_dir.as_ref().to_path_buf(),
        }
    }

    /// Get the multipart base directory
    fn multipart_base(&self) -> PathBuf {
        self.root_dir.join(".multipart")
    }

    /// Get the directory for a specific upload
    fn upload_dir(&self, bucket: &str, upload_id: &str) -> PathBuf {
        self.multipart_base().join(bucket).join(upload_id)
    }

    /// Get the metadata file path
    fn metadata_path(&self, bucket: &str, upload_id: &str) -> PathBuf {
        self.upload_dir(bucket, upload_id).join("metadata.json")
    }

    /// Get the part file path
    fn part_path(&self, bucket: &str, upload_id: &str, part_number: u32) -> PathBuf {
        self.upload_dir(bucket, upload_id)
            .join(format!("part-{}", part_number))
    }

    /// Create a new multipart upload
    pub async fn create_upload(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<MultipartUploadMetadata, CrabCakesError> {
        let upload_id = Uuid::new_v4().to_string();
        let metadata = MultipartUploadMetadata {
            upload_id: upload_id.clone(),
            bucket: bucket.to_string(),
            key: key.to_string(),
            initiated: Utc::now(),
        };

        let upload_dir = self.upload_dir(bucket, &upload_id);
        fs::create_dir_all(&upload_dir).await.map_err(|e: std::io::Error| {
            error!(upload_dir=%upload_dir.display(), "Failed to create upload directory: {}", e);
            CrabCakesError::other(&format!("Failed to create upload directory: {}", e))
        })?;

        let metadata_path = self.metadata_path(bucket, &upload_id);
        let metadata_json = serde_json::to_string_pretty(&metadata)
            .inspect_err(|e| error!("Failed to serialize metadata: {}", e))?;

        fs::write(&metadata_path, metadata_json)
            .await
            .inspect_err(|e| error!("Failed to write metadata: {}", e))?;

        debug!(
            upload_id = %upload_id,
            bucket = %bucket,
            key = %key,
            "Created multipart upload"
        );

        Ok(metadata)
    }

    /// Get metadata for an upload
    pub async fn get_metadata(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> Result<MultipartUploadMetadata, CrabCakesError> {
        let metadata_path = self.metadata_path(bucket, upload_id);
        let metadata_json = fs::read_to_string(&metadata_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CrabCakesError::Other("Upload not found".to_string())
            } else {
                CrabCakesError::Other(format!("Failed to read metadata: {e}"))
            }
        })?;

        serde_json::from_str(&metadata_json).map_err(|e| {
            error!("Failed to parse metadata: {}", e);
            e.into()
        })
    }

    /// Upload a part
    pub async fn upload_part(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        data: &[u8],
    ) -> Result<PartInfo, CrabCakesError> {
        // Validate part number
        if !(1..=10000).contains(&part_number) {
            return Err(CrabCakesError::other(&String::from(
                "Part number must be between 1 and 10000",
            )));
        }

        // Verify upload exists
        self.get_metadata(bucket, upload_id).await?;

        let part_path = self.part_path(bucket, upload_id, part_number);
        let mut file = fs::File::create(&part_path)
            .await
            .inspect_err(|e| error!("Failed to create part file: {}", e))?;

        file.write_all(data)
            .await
            .inspect_err(|e| error!("Failed to write part data: {}", e))?;

        file.sync_all()
            .await
            .inspect_err(|e| error!("Failed to sync part file: {}", e))?;

        // Generate ETag (MD5 hash of content)
        let etag = format!("\"{:x}\"", md5::compute(data));

        let part_info = PartInfo {
            part_number,
            etag,
            size: data.len() as u64,
            last_modified: Utc::now(),
        };

        debug!(
            upload_id = %upload_id,
            part_number = %part_number,
            size = %part_info.size,
            "Uploaded part"
        );

        Ok(part_info)
    }

    /// List all parts for an upload
    pub async fn list_parts(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> Result<Vec<PartInfo>, CrabCakesError> {
        // Verify upload exists
        self.get_metadata(bucket, upload_id).await?;

        let upload_dir = self.upload_dir(bucket, upload_id);
        let mut parts = Vec::new();

        let mut entries = fs::read_dir(&upload_dir).await.inspect_err(|e| {
            error!("Failed to read upload directory: {}", e);
        })?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .inspect_err(|e| error!("Failed to read directory entry: {}", e))?
        {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            if name_str.starts_with("part-")
                && let Some(part_num_str) = name_str.strip_prefix("part-")
                && let Ok(part_number) = part_num_str.parse::<u32>()
            {
                let metadata = entry
                    .metadata()
                    .await
                    .inspect_err(|e| error!("Failed to read file metadata: {}", e))?;

                let data = fs::read(entry.path())
                    .await
                    .inspect_err(|e| error!("Failed to read part file: {}", e))?;

                let etag = format!("\"{:x}\"", md5::compute(&data));

                parts.push(PartInfo {
                    part_number,
                    etag,
                    size: metadata.len(),
                    last_modified: Utc::now(), // Use current time as approximation
                });
            }
        }

        // Sort by part number
        parts.sort_by_key(|p| p.part_number);

        Ok(parts)
    }

    /// Abort a multipart upload (delete all state)
    pub async fn abort_upload(&self, bucket: &str, upload_id: &str) -> Result<(), CrabCakesError> {
        // Verify upload exists
        self.get_metadata(bucket, upload_id).await?;

        let upload_dir = self.upload_dir(bucket, upload_id);
        fs::remove_dir_all(&upload_dir).await.inspect_err(
            |e| error!(upload_dir=%upload_dir.display(), "Failed to remove upload directory: {e}"),
        )?;

        debug!(upload_id = %upload_id, "Aborted multipart upload");

        Ok(())
    }

    /// List all multipart uploads in a bucket
    pub async fn list_uploads(
        &self,
        bucket: &str,
    ) -> Result<Vec<MultipartUploadMetadata>, CrabCakesError> {
        let bucket_dir = self.multipart_base().join(bucket);

        // If bucket directory doesn't exist, return empty list
        if !bucket_dir.exists() {
            return Ok(Vec::new());
        }

        let mut uploads = Vec::new();

        let mut entries = fs::read_dir(&bucket_dir).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                return CrabCakesError::BucketNotFound(bucket.to_string());
            }
            error!(
                bucket_dir = %bucket_dir.display(),
                "Failed to read bucket directory: {}", e
            );
            e.into()
        })?;

        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await.inspect_err(
                |e| error!(filename=%entry.file_name().as_os_str().to_string_lossy(), "Failed to read file type: {}", e),
            )?;

            if file_type.is_dir() {
                let upload_id = entry.file_name().to_string_lossy().to_string();
                match self.get_metadata(bucket, &upload_id).await {
                    Ok(metadata) => uploads.push(metadata),
                    Err(e) => {
                        warn!(
                            upload_id = %upload_id,
                            error = %e,
                            "Failed to read upload metadata"
                        );
                    }
                }
            }
        }

        // Sort by initiated time (newest first)
        uploads.sort_by(|a, b| b.initiated.cmp(&a.initiated));

        Ok(uploads)
    }

    /// Complete a multipart upload by concatenating all parts
    pub async fn complete_upload(
        &self,
        bucket: &str,
        upload_id: &str,
        parts: &[(u32, String)], // (part_number, etag)
        dest_path: &Path,
    ) -> Result<String, CrabCakesError> {
        // Verify upload exists
        self.get_metadata(bucket, upload_id).await?;

        // Verify all parts exist and ETags match
        for (part_number, expected_etag) in parts {
            let part_path = self.part_path(bucket, upload_id, *part_number);
            if !part_path.exists() {
                return Err(CrabCakesError::other(&format!(
                    "Part {} not found",
                    part_number
                )));
            }

            let data = fs::read(&part_path).await.inspect_err(|e| {
                error!(part_path=%part_path.display(), "Failed to read part {}: {}", part_number, e)
            })?;

            let actual_etag = format!("\"{:x}\"", md5::compute(&data));
            if &actual_etag != expected_etag {
                return Err(CrabCakesError::other(&format!(
                    "ETag mismatch for part {}: expected {}, got {}",
                    part_number, expected_etag, actual_etag
                )));
            }
        }

        // Create destination file and concatenate all parts
        let mut dest_file = fs::File::create(dest_path).await.inspect_err(
            |e| error!(dest_path=%dest_path.display(), "Failed to create destination file: {}", e),
        )?;

        let mut all_data = Vec::new();

        for (part_number, _) in parts {
            let part_path = self.part_path(bucket, upload_id, *part_number);
            let data = fs::read(&part_path).await.inspect_err(|e| {
                error!(part_path=%part_path.display(), "Failed to read part {}: {}", part_number, e)
            })?;

            dest_file.write_all(&data).await.inspect_err(
                |e| error!(part_number=%part_number, "Failed to write part {}: {}", part_number, e),
            )?;

            all_data.extend_from_slice(&data);
        }

        dest_file.sync_all().await.inspect_err(
            |e| error!(dest_path=%dest_path.display(), "Failed to sync destination file: {}", e),
        )?;

        // Generate final ETag (MD5 of complete object)
        let final_etag = format!("\"{:x}\"", md5::compute(&all_data));

        // Clean up multipart state
        let upload_dir = self.upload_dir(bucket, upload_id);
        if let Err(e) = fs::remove_dir_all(&upload_dir).await {
            error!(error = %e, "Failed to cleanup multipart upload directory");
        }

        debug!(
            upload_id = %upload_id,
            parts = %parts.len(),
            total_size = %all_data.len(),
            "Completed multipart upload"
        );

        Ok(final_etag)
    }
}
