pub mod cli;
pub mod filesystem;
pub mod s3_handlers;
pub mod server;
pub mod xml_responses;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
        fs::create_dir_all(&dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            if ty.is_dir() {
                copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
            } else {
                fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
            }
        }
        Ok(())
    }

    fn setup_test_files() -> TempDir {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        copy_dir_all("testfiles", temp_dir.path()).expect("Failed to copy test files");
        temp_dir
    }

    #[tokio::test]
    async fn test_filesystem_service_file_exists() {
        let temp_dir = setup_test_files();
        let fs_service = filesystem::FilesystemService::new(temp_dir.path().to_path_buf());

        assert!(fs_service.file_exists("bucket1/test.txt"));
        assert!(!fs_service.file_exists("nonexistent.txt"));
    }

    #[tokio::test]
    async fn test_filesystem_service_get_metadata() {
        let temp_dir = setup_test_files();
        let fs_service = filesystem::FilesystemService::new(temp_dir.path().to_path_buf());

        let metadata = fs_service
            .get_file_metadata("bucket1/test.txt")
            .expect("File should exist");
        assert_eq!(metadata.size, 29); // "hello world this is test.txt\n" is 29 bytes
        assert!(metadata.etag.starts_with("\""));
        assert!(metadata.etag.ends_with("\""));
    }

    #[tokio::test]
    async fn test_list_directory() {
        let temp_dir = setup_test_files();
        let fs_service = filesystem::FilesystemService::new(temp_dir.path().to_path_buf());

        let (entries, _) = fs_service
            .list_directory(None, 1000, None)
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

        let response = xml_responses::ListBucketResponse::new(
            "test-bucket".to_string(),
            "".to_string(),
            1000,
            entries,
            None,
        );

        let xml = response.to_xml().expect("Should serialize to XML");
        assert!(xml.contains("<ListBucketResult>"));
        assert!(xml.contains("<Name>test-bucket</Name>"));
        assert!(xml.contains("<Key>test.txt</Key>"));
    }

    #[tokio::test]
    async fn test_list_buckets_xml() {
        let response = xml_responses::ListBucketsResponse::from_buckets(vec!["test-bucket".to_string()]);
        let xml = response.to_xml().expect("Should serialize to XML");

        assert!(xml.contains("<ListAllMyBucketsResult>"));
        assert!(xml.contains("<Name>test-bucket</Name>"));
        assert!(xml.contains("<Owner>"));
    }
}
