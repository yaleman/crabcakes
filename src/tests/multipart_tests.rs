//! Tests for multipart upload functionality

use crate::multipart::MultipartManager;

#[tokio::test]
async fn test_create_multipart_upload() {
    let (manager, _temp_dir) = MultipartManager::new_test();

    let metadata = manager
        .create_upload("test-bucket", "test-key.txt")
        .await
        .expect("Should create upload");

    assert_eq!(metadata.bucket, "test-bucket");
    assert_eq!(metadata.key, "test-key.txt");
    assert!(!metadata.upload_id.is_empty());
}

#[tokio::test]
async fn test_get_metadata_success() {
    let (manager, _temp_dir) = MultipartManager::new_test();

    let created = manager
        .create_upload("test-bucket", "test-key.txt")
        .await
        .expect("Should create upload");

    let retrieved = manager
        .get_metadata("test-bucket", &created.upload_id)
        .await
        .expect("Should get metadata");

    assert_eq!(retrieved.upload_id, created.upload_id);
    assert_eq!(retrieved.bucket, "test-bucket");
    assert_eq!(retrieved.key, "test-key.txt");
}

#[tokio::test]
async fn test_get_metadata_not_found() {
    let (manager, _temp_dir) = MultipartManager::new_test();

    let result = manager
        .get_metadata("test-bucket", "nonexistent-upload-id")
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_upload_part_success() {
    let (manager, _temp_dir) = MultipartManager::new_test();

    let metadata = manager
        .create_upload("test-bucket", "test-key.txt")
        .await
        .expect("Should create upload");

    let data = b"Hello, world!";
    let part_info = manager
        .upload_part("test-bucket", &metadata.upload_id, 1, data)
        .await
        .expect("Should upload part");

    assert_eq!(part_info.part_number, 1);
    assert_eq!(part_info.size, data.len() as u64);
    assert!(!part_info.etag.is_empty());
}

#[tokio::test]
async fn test_upload_part_invalid_number_zero() {
    let (manager, _temp_dir) = MultipartManager::new_test();

    let metadata = manager
        .create_upload("test-bucket", "test-key.txt")
        .await
        .expect("Should create upload");

    let data = b"test data";
    let result = manager
        .upload_part("test-bucket", &metadata.upload_id, 0, data)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_upload_part_invalid_number_too_high() {
    let (manager, _temp_dir) = MultipartManager::new_test();

    let metadata = manager
        .create_upload("test-bucket", "test-key.txt")
        .await
        .expect("Should create upload");

    let data = b"test data";
    let result = manager
        .upload_part("test-bucket", &metadata.upload_id, 10001, data)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_upload_part_nonexistent_upload() {
    let (manager, _temp_dir) = MultipartManager::new_test();

    let data = b"test data";
    let result = manager
        .upload_part("test-bucket", "nonexistent-upload-id", 1, data)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_upload_multiple_parts() {
    let (manager, _temp_dir) = MultipartManager::new_test();

    let metadata = manager
        .create_upload("test-bucket", "test-key.txt")
        .await
        .expect("Should create upload");

    // Upload three parts
    let part1 = manager
        .upload_part("test-bucket", &metadata.upload_id, 1, b"Part 1 data")
        .await
        .expect("Should upload part 1");

    let part2 = manager
        .upload_part("test-bucket", &metadata.upload_id, 2, b"Part 2 data")
        .await
        .expect("Should upload part 2");

    let part3 = manager
        .upload_part("test-bucket", &metadata.upload_id, 3, b"Part 3 data")
        .await
        .expect("Should upload part 3");

    assert_eq!(part1.part_number, 1);
    assert_eq!(part2.part_number, 2);
    assert_eq!(part3.part_number, 3);
}

#[tokio::test]
async fn test_list_parts_empty() {
    let (manager, _temp_dir) = MultipartManager::new_test();

    let metadata = manager
        .create_upload("test-bucket", "test-key.txt")
        .await
        .expect("Should create upload");

    let parts = manager
        .list_parts("test-bucket", &metadata.upload_id)
        .await
        .expect("Should list parts");

    assert_eq!(parts.len(), 0);
}

#[tokio::test]
async fn test_list_parts_multiple() {
    let (manager, _temp_dir) = MultipartManager::new_test();

    let metadata = manager
        .create_upload("test-bucket", "test-key.txt")
        .await
        .expect("Should create upload");

    // Upload parts out of order
    manager
        .upload_part("test-bucket", &metadata.upload_id, 3, b"Part 3")
        .await
        .expect("Should upload part 3");

    manager
        .upload_part("test-bucket", &metadata.upload_id, 1, b"Part 1")
        .await
        .expect("Should upload part 1");

    manager
        .upload_part("test-bucket", &metadata.upload_id, 2, b"Part 2")
        .await
        .expect("Should upload part 2");

    let parts = manager
        .list_parts("test-bucket", &metadata.upload_id)
        .await
        .expect("Should list parts");

    assert_eq!(parts.len(), 3);
    // Verify parts are sorted by part number
    assert_eq!(parts[0].part_number, 1);
    assert_eq!(parts[1].part_number, 2);
    assert_eq!(parts[2].part_number, 3);
}

#[tokio::test]
async fn test_list_parts_nonexistent_upload() {
    let (manager, _temp_dir) = MultipartManager::new_test();

    let result = manager
        .list_parts("test-bucket", "nonexistent-upload-id")
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_abort_upload_success() {
    let (manager, temp_dir) = MultipartManager::new_test();

    let metadata = manager
        .create_upload("test-bucket", "test-key.txt")
        .await
        .expect("Should create upload");

    // Upload a part
    manager
        .upload_part("test-bucket", &metadata.upload_id, 1, b"test data")
        .await
        .expect("Should upload part");

    // Abort the upload
    manager
        .abort_upload("test-bucket", &metadata.upload_id)
        .await
        .expect("Should abort upload");

    // Verify upload directory is gone
    let upload_dir = temp_dir
        .path()
        .join(".multipart")
        .join("test-bucket")
        .join(&metadata.upload_id);
    assert!(!upload_dir.exists());
}

#[tokio::test]
async fn test_abort_nonexistent_upload() {
    let (manager, _temp_dir) = MultipartManager::new_test();

    let result = manager
        .abort_upload("test-bucket", "nonexistent-upload-id")
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_list_uploads_empty_bucket() {
    let (manager, _temp_dir) = MultipartManager::new_test();

    let uploads = manager
        .list_uploads("empty-bucket")
        .await
        .expect("Should list uploads");

    assert_eq!(uploads.len(), 0);
}

#[tokio::test]
async fn test_list_uploads_multiple() {
    let (manager, _temp_dir) = MultipartManager::new_test();

    // Create multiple uploads
    let upload1 = manager
        .create_upload("test-bucket", "file1.txt")
        .await
        .expect("Should create upload 1");

    // Small delay to ensure different timestamps
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let upload2 = manager
        .create_upload("test-bucket", "file2.txt")
        .await
        .expect("Should create upload 2");

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let upload3 = manager
        .create_upload("test-bucket", "file3.txt")
        .await
        .expect("Should create upload 3");

    let uploads = manager
        .list_uploads("test-bucket")
        .await
        .expect("Should list uploads");

    assert_eq!(uploads.len(), 3);

    // Verify uploads are sorted by initiated time (newest first)
    assert_eq!(uploads[0].upload_id, upload3.upload_id);
    assert_eq!(uploads[1].upload_id, upload2.upload_id);
    assert_eq!(uploads[2].upload_id, upload1.upload_id);
}

#[tokio::test]
async fn test_complete_upload_success() {
    let (manager, temp_dir) = MultipartManager::new_test();

    let metadata = manager
        .create_upload("test-bucket", "test-key.txt")
        .await
        .expect("Should create upload");

    // Upload parts
    let part1 = manager
        .upload_part("test-bucket", &metadata.upload_id, 1, b"Hello, ")
        .await
        .expect("Should upload part 1");

    let part2 = manager
        .upload_part("test-bucket", &metadata.upload_id, 2, b"world!")
        .await
        .expect("Should upload part 2");

    // Complete the upload
    let dest_path = temp_dir.path().join("completed-file.txt");
    let parts = vec![
        (1, part1.etag.clone()),
        (2, part2.etag.clone()),
    ];

    let final_etag = manager
        .complete_upload("test-bucket", &metadata.upload_id, &parts, &dest_path)
        .await
        .expect("Should complete upload");

    assert!(!final_etag.is_empty());
    assert!(dest_path.exists());

    // Verify file contents
    let contents = tokio::fs::read_to_string(&dest_path)
        .await
        .expect("Should read completed file");
    assert_eq!(contents, "Hello, world!");
}

#[tokio::test]
async fn test_complete_upload_missing_part() {
    let (manager, temp_dir) = MultipartManager::new_test();

    let metadata = manager
        .create_upload("test-bucket", "test-key.txt")
        .await
        .expect("Should create upload");

    // Upload only part 1
    let part1 = manager
        .upload_part("test-bucket", &metadata.upload_id, 1, b"Part 1")
        .await
        .expect("Should upload part 1");

    // Try to complete with part 2 that doesn't exist
    let dest_path = temp_dir.path().join("completed-file.txt");
    let parts = vec![
        (1, part1.etag.clone()),
        (2, "\"fake-etag\"".to_string()),
    ];

    let result = manager
        .complete_upload("test-bucket", &metadata.upload_id, &parts, &dest_path)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_complete_upload_etag_mismatch() {
    let (manager, temp_dir) = MultipartManager::new_test();

    let metadata = manager
        .create_upload("test-bucket", "test-key.txt")
        .await
        .expect("Should create upload");

    // Upload part
    manager
        .upload_part("test-bucket", &metadata.upload_id, 1, b"Part 1")
        .await
        .expect("Should upload part 1");

    // Try to complete with wrong ETag
    let dest_path = temp_dir.path().join("completed-file.txt");
    let parts = vec![(1, "\"wrong-etag\"".to_string())];

    let result = manager
        .complete_upload("test-bucket", &metadata.upload_id, &parts, &dest_path)
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_complete_upload_cleans_up() {
    let (manager, temp_dir) = MultipartManager::new_test();

    let metadata = manager
        .create_upload("test-bucket", "test-key.txt")
        .await
        .expect("Should create upload");

    let part1 = manager
        .upload_part("test-bucket", &metadata.upload_id, 1, b"test data")
        .await
        .expect("Should upload part");

    let dest_path = temp_dir.path().join("completed-file.txt");
    let parts = vec![(1, part1.etag.clone())];

    manager
        .complete_upload("test-bucket", &metadata.upload_id, &parts, &dest_path)
        .await
        .expect("Should complete upload");

    // Verify upload directory is cleaned up
    let upload_dir = temp_dir
        .path()
        .join(".multipart")
        .join("test-bucket")
        .join(&metadata.upload_id);
    assert!(!upload_dir.exists());
}

#[tokio::test]
async fn test_full_multipart_workflow() {
    let (manager, temp_dir) = MultipartManager::new_test();

    // 1. Create upload
    let metadata = manager
        .create_upload("test-bucket", "large-file.bin")
        .await
        .expect("Should create upload");

    // 2. Upload multiple parts
    let part1 = manager
        .upload_part("test-bucket", &metadata.upload_id, 1, b"First part ")
        .await
        .expect("Should upload part 1");

    let part2 = manager
        .upload_part("test-bucket", &metadata.upload_id, 2, b"Second part ")
        .await
        .expect("Should upload part 2");

    let part3 = manager
        .upload_part("test-bucket", &metadata.upload_id, 3, b"Third part")
        .await
        .expect("Should upload part 3");

    // 3. List parts to verify
    let parts_list = manager
        .list_parts("test-bucket", &metadata.upload_id)
        .await
        .expect("Should list parts");
    assert_eq!(parts_list.len(), 3);

    // 4. Complete upload
    let dest_path = temp_dir.path().join("completed-file.bin");
    let parts = vec![
        (1, part1.etag),
        (2, part2.etag),
        (3, part3.etag),
    ];

    let final_etag = manager
        .complete_upload("test-bucket", &metadata.upload_id, &parts, &dest_path)
        .await
        .expect("Should complete upload");

    assert!(!final_etag.is_empty());
    assert!(dest_path.exists());

    // 5. Verify final content
    let contents = tokio::fs::read_to_string(&dest_path)
        .await
        .expect("Should read completed file");
    assert_eq!(contents, "First part Second part Third part");
}

#[tokio::test]
async fn test_full_multipart_abort_workflow() {
    let (manager, temp_dir) = MultipartManager::new_test();

    // 1. Create upload
    let metadata = manager
        .create_upload("test-bucket", "aborted-file.bin")
        .await
        .expect("Should create upload");

    // 2. Upload some parts
    manager
        .upload_part("test-bucket", &metadata.upload_id, 1, b"Part 1")
        .await
        .expect("Should upload part 1");

    manager
        .upload_part("test-bucket", &metadata.upload_id, 2, b"Part 2")
        .await
        .expect("Should upload part 2");

    // 3. List parts to verify they exist
    let parts_list = manager
        .list_parts("test-bucket", &metadata.upload_id)
        .await
        .expect("Should list parts");
    assert_eq!(parts_list.len(), 2);

    // 4. Abort the upload
    manager
        .abort_upload("test-bucket", &metadata.upload_id)
        .await
        .expect("Should abort upload");

    // 5. Verify everything is cleaned up
    let upload_dir = temp_dir
        .path()
        .join(".multipart")
        .join("test-bucket")
        .join(&metadata.upload_id);
    assert!(!upload_dir.exists());

    // 6. Verify we can't access the upload anymore
    let result = manager
        .get_metadata("test-bucket", &metadata.upload_id)
        .await;
    assert!(result.is_err());
}
