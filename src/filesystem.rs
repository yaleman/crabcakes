//! Filesystem-backed S3 storage operations.
//!
//! Implements bucket and object operations using the local filesystem,
//! with metadata extraction and validation.

use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use mime_guess::MimeGuess;
use tokio::fs::{self, read_dir};
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

use crate::constants::RESERVED_BUCKET_NAMES;

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub path: PathBuf,
    pub size: u64,
    pub last_modified: DateTime<Utc>,
    pub content_type: String,
    pub etag: String,
}

#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub key: String,
    pub size: u64,
    pub last_modified: DateTime<Utc>,
    pub etag: String,
}

pub struct FilesystemService {
    root_dir: PathBuf,
}

/// Check if a bucket name should be excluded from listing or creation.
/// Returns true if the bucket name should be excluded (reserved, hidden, or system directory).
fn is_bucket_name_excluded(name: &str) -> bool {
    // Reserved bucket names
    if RESERVED_BUCKET_NAMES.contains(&name) {
        return true;
    }

    // Hidden directories (starting with .)
    if name.starts_with('.') {
        return true;
    }

    // System directories
    if name == "lost+found" {
        return true;
    }

    false
}

impl FilesystemService {
    pub fn new(root_dir: PathBuf) -> Self {
        Self { root_dir }
    }

    /// Resolve a key to an absolute filesystem path
    pub fn resolve_path(&self, key: &str) -> PathBuf {
        self.root_dir.join(key)
    }

    pub async fn get_file_metadata(&self, key: &str) -> Result<FileMetadata, std::io::Error> {
        let file_path = self.root_dir.join(key);
        debug!(key = %key, path = ?file_path, "Getting file metadata");

        let metadata = fs::metadata(&file_path).await?;

        if !metadata.is_file() {
            warn!(key = %key, "Path is not a file");
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Path is not a file",
            ));
        }

        let last_modified = metadata
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let last_modified =
            DateTime::from_timestamp(last_modified.as_secs() as i64, 0).unwrap_or_else(Utc::now);

        let content_type = MimeGuess::from_path(&file_path)
            .first_or_octet_stream()
            .to_string();

        let etag = format!("\"{}\"", self.calculate_etag(&metadata));

        Ok(FileMetadata {
            path: file_path,
            size: metadata.len(),
            last_modified,
            content_type,
            etag,
        })
    }

    pub fn file_exists(&self, key: &str) -> bool {
        let file_path = self.root_dir.join(key);
        file_path.exists() && file_path.is_file()
    }

    pub async fn list_buckets(&self) -> Result<Vec<String>, std::io::Error> {
        debug!("Listing buckets (top-level directories)");
        let mut buckets = Vec::new();

        let mut readdir = read_dir(&self.root_dir).await?;
        while let Some(entry) = readdir.next_entry().await? {
            if entry.file_type().await?.is_dir()
                && let Some(name) = entry.file_name().to_str()
            {
                // Filter out excluded bucket names
                if is_bucket_name_excluded(name) {
                    debug!(bucket = %name, "Skipping excluded bucket name");
                    continue;
                }

                buckets.push(name.to_string());
            }
        }

        buckets.sort();
        debug!(count = buckets.len(), buckets = ?buckets, "Found buckets");
        Ok(buckets)
    }

    pub async fn list_directory(
        &self,
        prefix: Option<&str>,
        max_keys: usize,
        continuation_token: Option<&str>,
    ) -> Result<(Vec<DirectoryEntry>, Option<String>), std::io::Error> {
        debug!(
            prefix = ?prefix,
            max_keys = max_keys,
            continuation_token = ?continuation_token,
            "Listing directory"
        );
        let mut entries = Vec::new();
        let start_after = continuation_token.unwrap_or("");

        async fn collect_files(
            dir: &Path,
            root: &Path,
            prefix: Option<&str>,
            entries: &mut Vec<DirectoryEntry>,
            start_after: &str,
        ) -> Result<(), std::io::Error> {
            let mut reader = fs::read_dir(dir).await?;
            while let Some(entry) = reader.next_entry().await? {
                let path = entry.path();

                if path.is_file() {
                    let relative_path = path.strip_prefix(root).map_err(std::io::Error::other)?;
                    let key = relative_path.to_string_lossy().to_string();

                    if let Some(prefix) = prefix
                        && !key.starts_with(prefix)
                    {
                        continue;
                    }

                    if key.as_str() <= start_after {
                        continue;
                    }

                    let metadata = entry.metadata().await?;
                    let last_modified = metadata
                        .modified()?
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default();
                    let last_modified = DateTime::from_timestamp(last_modified.as_secs() as i64, 0)
                        .unwrap_or_else(Utc::now);

                    let etag = format!("\"{}\"", calculate_etag_from_metadata(&metadata));

                    entries.push(DirectoryEntry {
                        key,
                        size: metadata.len(),
                        last_modified,
                        etag,
                    });
                } else if path.is_dir() {
                    Box::pin(collect_files(&path, root, prefix, entries, start_after)).await?;
                }
            }
            Ok(())
        }

        collect_files(
            &self.root_dir,
            &self.root_dir,
            prefix,
            &mut entries,
            start_after,
        )
        .await?;

        entries.sort_by(|a, b| a.key.cmp(&b.key));

        let mut next_continuation_token = None;
        if entries.len() > max_keys {
            next_continuation_token = Some(entries[max_keys - 1].key.clone());
            entries.truncate(max_keys);
        }

        Ok((entries, next_continuation_token))
    }

    fn calculate_etag(&self, metadata: &Metadata) -> String {
        calculate_etag_from_metadata(metadata)
    }

    pub async fn write_file(&self, key: &str, body: &[u8]) -> Result<FileMetadata, std::io::Error> {
        let file_path = self.root_dir.join(key);
        debug!(key = %key, path = ?file_path, size = body.len(), "Writing file");

        // Create parent directories if they don't exist
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Write file atomically by writing to temp file and renaming
        let temp_path = file_path.with_extension("tmp");
        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(body).await?;
        file.sync_all().await?;
        drop(file);

        // Atomic rename
        fs::rename(&temp_path, &file_path).await?;

        // Get metadata for the newly written file
        self.get_file_metadata(key).await
    }

    pub async fn create_bucket(&self, bucket: &str) -> Result<(), std::io::Error> {
        debug!(bucket = %bucket, "Creating bucket");

        // Check if bucket name is excluded (reserved, hidden, or system directory)
        if is_bucket_name_excluded(bucket) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Bucket name '{}' is reserved and cannot be used", bucket),
            ));
        }

        // Validate bucket name
        if bucket.is_empty() || bucket.len() > 63 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Bucket name must be between 1 and 63 characters",
            ));
        }

        // Check for valid characters (lowercase letters, numbers, hyphens)
        if !bucket
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Bucket name can only contain lowercase letters, numbers, and hyphens",
            ));
        }

        // Bucket name cannot start or end with a hyphen
        if bucket.starts_with('-') || bucket.ends_with('-') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Bucket name cannot start or end with a hyphen",
            ));
        }

        let bucket_path = self.root_dir.join(bucket);

        // Check if bucket already exists
        if bucket_path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "Bucket already exists",
            ));
        }

        // Create the directory
        fs::create_dir(&bucket_path).await?;
        debug!(bucket = %bucket, "Bucket created successfully");
        Ok(())
    }

    pub async fn delete_bucket(&self, bucket: &str) -> Result<(), std::io::Error> {
        debug!(bucket = %bucket, "Deleting bucket");
        let bucket_path = self.root_dir.join(bucket);

        // Check if bucket exists
        if !bucket_path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Bucket does not exist",
            ));
        }

        // Check if it's a directory
        if !bucket_path.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Path is not a bucket",
            ));
        }

        // Check if bucket is empty
        let mut entries = fs::read_dir(&bucket_path).await?;
        if entries.next_entry().await?.is_some() {
            return Err(std::io::Error::other("Bucket is not empty"));
        }

        // Remove the directory
        fs::remove_dir(&bucket_path).await?;
        debug!(bucket = %bucket, "Bucket deleted successfully");
        Ok(())
    }

    pub async fn delete_file(&self, key: &str) -> Result<(), std::io::Error> {
        let file_path = self.root_dir.join(key);
        debug!(key = %key, path = ?file_path, "Deleting file");

        // S3 behavior: deleting a non-existent object is a success
        if !file_path.exists() {
            debug!(key = %key, "File does not exist, returning success (S3 behavior)");
            return Ok(());
        }

        // Ensure it's a file, not a directory
        if file_path.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot delete a directory as an object",
            ));
        }

        // Delete the file
        fs::remove_file(&file_path).await?;
        debug!(key = %key, "File deleted successfully");
        Ok(())
    }

    pub fn bucket_exists(&self, bucket: &str) -> bool {
        let bucket_path = self.root_dir.join(bucket);
        bucket_path.exists() && bucket_path.is_dir()
    }

    pub async fn copy_file(
        &self,
        source_key: &str,
        dest_key: &str,
    ) -> Result<FileMetadata, std::io::Error> {
        let source_path = self.root_dir.join(source_key);
        let dest_path = self.root_dir.join(dest_key);

        debug!(source = %source_key, dest = %dest_key, "Copying file");

        // Ensure source file exists
        if !source_path.exists() || !source_path.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Source file does not exist",
            ));
        }

        // Ensure destination directory exists
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Copy the file
        fs::copy(&source_path, &dest_path).await?;
        debug!(source = %source_key, dest = %dest_key, "File copied successfully");

        // Get metadata for the newly copied file
        self.get_file_metadata(dest_key).await
    }
}

fn calculate_etag_from_metadata(metadata: &Metadata) -> String {
    format!(
        "{:x}-{:x}",
        metadata.len(),
        metadata
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH)
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    )
}
