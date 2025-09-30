use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use mime_guess::MimeGuess;

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

impl FilesystemService {
    pub fn new(root_dir: PathBuf) -> Self {
        Self { root_dir }
    }

    pub fn get_file_metadata(&self, key: &str) -> Result<FileMetadata, std::io::Error> {
        let file_path = self.root_dir.join(key);
        let metadata = fs::metadata(&file_path)?;

        if !metadata.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Path is not a file",
            ));
        }

        let last_modified = metadata
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let last_modified = DateTime::from_timestamp(last_modified.as_secs() as i64, 0)
            .unwrap_or_else(Utc::now);

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

    pub fn list_directory(&self, prefix: Option<&str>, max_keys: usize, continuation_token: Option<&str>) -> Result<(Vec<DirectoryEntry>, Option<String>), std::io::Error> {
        let mut entries = Vec::new();
        let start_after = continuation_token.unwrap_or("");

        fn collect_files(
            dir: &Path,
            root: &Path,
            prefix: Option<&str>,
            entries: &mut Vec<DirectoryEntry>,
            start_after: &str,
        ) -> Result<(), std::io::Error> {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.is_file() {
                    let relative_path = path.strip_prefix(root).unwrap();
                    let key = relative_path.to_string_lossy().to_string();

                    if let Some(prefix) = prefix
                        && !key.starts_with(prefix) {
                            continue;
                        }

                    if key.as_str() <= start_after {
                        continue;
                    }

                    let metadata = entry.metadata()?;
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
                    collect_files(&path, root, prefix, entries, start_after)?;
                }
            }
            Ok(())
        }

        collect_files(&self.root_dir, &self.root_dir, prefix, &mut entries, start_after)?;

        entries.sort_by(|a, b| a.key.cmp(&b.key));

        let mut next_continuation_token = None;
        if entries.len() > max_keys {
            next_continuation_token = Some(entries[max_keys - 1].key.clone());
            entries.truncate(max_keys);
        }

        Ok((entries, next_continuation_token))
    }

    fn calculate_etag(&self, metadata: &fs::Metadata) -> String {
        calculate_etag_from_metadata(metadata)
    }
}

fn calculate_etag_from_metadata(metadata: &fs::Metadata) -> String {
    format!("{:x}-{:x}",
        metadata.len(),
        metadata.modified()
            .unwrap_or(SystemTime::UNIX_EPOCH)
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    )
}