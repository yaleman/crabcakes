pub(crate) mod db_tests;
pub(crate) mod multipart_tests;
pub(crate) mod policy_tests;
pub(crate) mod request_handler_tests;
pub(crate) mod server_tests;
pub(crate) mod web_handlers_tests;

use crate::constants::SECRET_ACCESS_KEY_LENGTH;
use crate::web::xml_responses::{ListAllMyBucketsResult, ListBucketResponse, to_xml};

use super::*;
use std::collections::HashSet;
use std::path::PathBuf;
use tempfile::TempDir;
use tokio::fs;
use tracing::debug;

pub(crate) async fn copy_dir_all(src: PathBuf, dst: PathBuf) -> std::io::Result<()> {
    let mut targets = vec![(src, dst)];
    let mut dirs_done = HashSet::new();

    while let Some((src_dir, dest_dir)) = targets.pop() {
        if dirs_done.contains(&src_dir) {
            debug!(
                src = %src_dir.display(),
                dest = %dest_dir.display(),
                "Skipping done directory"
            );
            continue;
        } else {
            debug!(
                src = %src_dir.display(),
                dest = %dest_dir.display(),
                "Copying directory"
            );
        }
        fs::create_dir_all(&dest_dir).await?;
        let mut dir_reader = fs::read_dir(&src_dir).await?;
        while let Some(entry) = dir_reader.next_entry().await? {
            let ty = entry.file_type().await?;
            if ty.is_dir() {
                debug!(
                    "Found a new directory: {:?}",
                    src_dir.join(entry.file_name())
                );
                if !dirs_done.contains(&entry.path()) {
                    targets.push((
                        src_dir.join(entry.file_name()),
                        dest_dir.join(entry.file_name()),
                    ));
                    fs::create_dir_all(dest_dir.join(entry.file_name())).await?;
                }
            } else {
                fs::copy(entry.path(), dest_dir.join(entry.file_name())).await?;
            }
        }
        debug!("Finished copying directory: {:?}", src_dir.as_path());
        dirs_done.insert(src_dir);
    }
    Ok(())
}

pub(crate) async fn setup_test_files() -> TempDir {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    copy_dir_all("testfiles".into(), temp_dir.path().into())
        .await
        .expect("Failed to copy test files");
    temp_dir
}

#[tokio::test]
async fn test_filesystem_service_file_exists() {
    let temp_dir = setup_test_files().await;
    let fs_service = filesystem::FilesystemService::new(temp_dir.path().to_path_buf())
        .expect("Failed to create filesystem service");

    assert!(fs_service.file_exists("bucket1/test.txt"));
    assert!(!fs_service.file_exists("nonexistent.txt"));
}

#[tokio::test]
async fn test_filesystem_service_get_metadata() {
    let temp_dir = setup_test_files().await;
    let fs_service = filesystem::FilesystemService::new(temp_dir.path().to_path_buf())
        .expect("Failed to create filesystem service");

    let metadata = fs_service
        .get_file_metadata("bucket1/test.txt")
        .await
        .expect("File should exist");
    assert_eq!(metadata.size, 29); // "hello world this is test.txt\n" is 29 bytes
    assert!(metadata.etag.starts_with("\""));
    assert!(metadata.etag.ends_with("\""));
}

#[tokio::test]
async fn test_list_directory() {
    let temp_dir = setup_test_files().await;
    let fs_service = filesystem::FilesystemService::new(temp_dir.path().to_path_buf())
        .expect("Failed to create filesystem service");

    let (entries, _) = fs_service
        .list_directory(None, 1000, None)
        .await
        .expect("Should list directory");
    assert!(!entries.is_empty());
    assert!(entries.iter().any(|e| e.key == "bucket1/test.txt"));
    assert!(entries.iter().any(|e| e.key == "bucket2/hello-world.json"));
}

#[tokio::test]
async fn test_xml_responses() {
    let entries = vec![filesystem::DirectoryEntry {
        key: "test.txt".to_string(),
        size: 29,
        last_modified: chrono::Utc::now(),
        etag: "\"abc123\"".to_string(),
    }];

    let response = ListBucketResponse::new(
        "test-bucket".to_string(),
        "".to_string(),
        1000,
        entries,
        None,
    );

    let xml = to_xml(response).expect("Should serialize to XML");
    assert!(xml.contains("<ListBucketResult>"));
    assert!(xml.contains("<Name>test-bucket</Name>"));
    assert!(xml.contains("<Key>test.txt</Key>"));
}

#[tokio::test]
async fn test_list_buckets_xml() {
    let response = ListAllMyBucketsResult::from_buckets(vec!["test-bucket".to_string()]);
    let xml = to_xml(response).expect("Should serialize to XML");
    dbg!(&xml);
    assert!(xml.contains("<ListAllMyBucketsResult>"));
    assert!(xml.contains("<Name>test-bucket</Name>"));
    assert!(xml.contains("<Owner><ID>crabcakes</ID></Owner>"));
}

#[test]
fn test_generate_temp_credentials() {
    for _ in 0..1000 {
        let (access_key_id, secret_access_key) = generate_temp_credentials();

        assert_eq!(access_key_id.len(), TEMP_ACCESS_KEY_LENGTH);
        assert_eq!(secret_access_key.len(), SECRET_ACCESS_KEY_LENGTH);
        // Check that access key ID is alphanumeric
        assert!(access_key_id.chars().all(|c| c.is_ascii_alphanumeric()));

        assert!(
            access_key_id
                .chars()
                .next()
                .expect("Access key ID is empty")
                .is_ascii_alphabetic()
        );

        assert!(
            secret_access_key
                .as_bytes()
                .iter()
                .all(|c| SECRET_CHARS.contains(c))
        );
    }
}
