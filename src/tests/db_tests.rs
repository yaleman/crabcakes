//! Tests for database module (tags, migrations, DBService)

use std::sync::Arc;
use tempfile::TempDir;

use crate::{
    constants::TEST_ALLOWED_BUCKET,
    db::{DBService, initialize_database, initialize_in_memory_database},
};

/// Create an in-memory test database
async fn setup_test_db() -> Arc<DBService> {
    Arc::new(DBService::new(Arc::new(
        initialize_in_memory_database().await,
    )))
}

#[tokio::test]
async fn test_database_initialization() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db = initialize_database(temp_dir.path()).await;
    assert!(db.is_ok(), "Database initialization should succeed");

    // Verify database file was created
    let db_path = temp_dir.path().join("crabcakes.sqlite3");
    assert!(db_path.exists(), "Database file should be created");
}

#[tokio::test]
async fn test_put_tags_valid() {
    let db_service = setup_test_db().await;

    let tags = vec![
        ("Environment".to_string(), "Test".to_string()),
        ("Project".to_string(), "Crabcakes".to_string()),
    ];

    let result = db_service
        .put_tags("test-bucket", "test-key.txt", tags)
        .await;
    assert!(result.is_ok(), "Should successfully store valid tags");
}

#[tokio::test]
async fn test_get_tags_existing() {
    let db_service = setup_test_db().await;

    // Put tags first
    let tags = vec![
        ("Environment".to_string(), "Production".to_string()),
        ("Owner".to_string(), "Alice".to_string()),
    ];
    db_service
        .put_tags(TEST_ALLOWED_BUCKET, "file.txt", tags.clone())
        .await
        .expect("Should store tags");

    // Get tags
    let retrieved = db_service
        .get_tags(TEST_ALLOWED_BUCKET, "file.txt")
        .await
        .expect("Should retrieve tags");

    assert_eq!(retrieved.len(), 2, "Should have 2 tags");
    assert!(
        retrieved.contains(&("Environment".to_string(), "Production".to_string())),
        "Should contain Environment tag"
    );
    assert!(
        retrieved.contains(&("Owner".to_string(), "Alice".to_string())),
        "Should contain Owner tag"
    );
}

#[tokio::test]
async fn test_get_tags_nonexistent() {
    let db_service = setup_test_db().await;

    let tags = db_service
        .get_tags(TEST_ALLOWED_BUCKET, "nonexistent.txt")
        .await
        .expect("Should return empty tag set");

    assert_eq!(
        tags.len(),
        0,
        "Should return empty tag set for nonexistent object"
    );
}

#[tokio::test]
async fn test_delete_tags() {
    let db_service = setup_test_db().await;

    // Put tags first
    let tags = vec![("Key1".to_string(), "Value1".to_string())];
    db_service
        .put_tags(TEST_ALLOWED_BUCKET, "file.txt", tags)
        .await
        .expect("Should store tags");

    // Delete tags
    let result = db_service
        .delete_tags(TEST_ALLOWED_BUCKET, "file.txt")
        .await;
    assert!(result.is_ok(), "Should delete tags successfully");

    // Verify tags are deleted
    let retrieved = db_service
        .get_tags(TEST_ALLOWED_BUCKET, "file.txt")
        .await
        .expect("Should retrieve tags");
    assert_eq!(retrieved.len(), 0, "Tags should be deleted");
}

#[tokio::test]
async fn test_put_tags_replaces_existing() {
    let db_service = setup_test_db().await;

    // Put initial tags
    let initial_tags = vec![
        ("Tag1".to_string(), "Value1".to_string()),
        ("Tag2".to_string(), "Value2".to_string()),
    ];
    db_service
        .put_tags(TEST_ALLOWED_BUCKET, "file.txt", initial_tags)
        .await
        .expect("Should store initial tags");

    // Replace with new tags
    let new_tags = vec![("NewTag".to_string(), "NewValue".to_string())];
    db_service
        .put_tags(TEST_ALLOWED_BUCKET, "file.txt", new_tags)
        .await
        .expect("Should replace tags");

    // Verify only new tags exist
    let retrieved = db_service
        .get_tags(TEST_ALLOWED_BUCKET, "file.txt")
        .await
        .expect("Should retrieve tags");
    assert_eq!(retrieved.len(), 1, "Should have only 1 tag");
    assert_eq!(
        retrieved[0],
        ("NewTag".to_string(), "NewValue".to_string()),
        "Should contain only new tag"
    );
}

#[tokio::test]
async fn test_put_tags_too_many() {
    let db_service = setup_test_db().await;

    // Create 11 tags (exceeds limit of 10)
    let tags: Vec<(String, String)> = (0..11)
        .map(|i| (format!("Tag{}", i), format!("Value{}", i)))
        .collect();

    let result = db_service
        .put_tags(TEST_ALLOWED_BUCKET, "file.txt", tags)
        .await;
    assert!(result.is_err(), "Should reject more than 10 tags");
    assert!(
        result
            .expect_err("Should have returned error")
            .to_string()
            .contains("Too many tags"),
        "Error should mention too many tags"
    );
}

#[tokio::test]
async fn test_put_tags_empty_key() {
    let db_service = setup_test_db().await;

    let tags = vec![("".to_string(), "Value".to_string())];
    let result = db_service
        .put_tags(TEST_ALLOWED_BUCKET, "file.txt", tags)
        .await;

    assert!(result.is_err(), "Should reject empty tag key");
    assert!(
        result
            .expect_err("Should have returned error")
            .to_string()
            .contains("cannot be empty"),
        "Error should mention empty key"
    );
}

#[tokio::test]
async fn test_put_tags_key_too_long() {
    let db_service = setup_test_db().await;

    // Create a key with 129 characters (exceeds limit of 128)
    let long_key = "a".repeat(129);
    let tags = vec![(long_key, "Value".to_string())];
    let result = db_service
        .put_tags(TEST_ALLOWED_BUCKET, "file.txt", tags)
        .await;

    assert!(result.is_err(), "Should reject tag key > 128 characters");
    assert!(
        result
            .expect_err("Should have returned error")
            .to_string()
            .contains("Tag key too long"),
        "Error should mention key too long"
    );
}

#[tokio::test]
async fn test_put_tags_value_too_long() {
    let db_service = setup_test_db().await;

    // Create a value with 257 characters (exceeds limit of 256)
    let long_value = "b".repeat(257);
    let tags = vec![("Key".to_string(), long_value)];
    let result = db_service
        .put_tags(TEST_ALLOWED_BUCKET, "file.txt", tags)
        .await;

    assert!(result.is_err(), "Should reject tag value > 256 characters");
    assert!(
        result
            .expect_err("Should have returned error")
            .to_string()
            .contains("Tag value too long"),
        "Error should mention value too long"
    );
}

#[tokio::test]
async fn test_put_tags_max_valid_lengths() {
    let db_service = setup_test_db().await;

    // Test maximum valid lengths (128 char key, 256 char value)
    let max_key = "k".repeat(128);
    let max_value = "v".repeat(256);
    let tags = vec![(max_key.clone(), max_value.clone())];

    let result = db_service
        .put_tags(TEST_ALLOWED_BUCKET, "file.txt", tags)
        .await;
    assert!(result.is_ok(), "Should accept max valid tag lengths");

    // Verify tags were stored
    let retrieved = db_service
        .get_tags(TEST_ALLOWED_BUCKET, "file.txt")
        .await
        .expect("Should retrieve tags");
    assert_eq!(retrieved.len(), 1);
    assert_eq!(retrieved[0].0, max_key);
    assert_eq!(retrieved[0].1, max_value);
}

#[tokio::test]
async fn test_tags_isolated_by_bucket_and_key() {
    let db_service = setup_test_db().await;

    // Put tags for different objects
    let tags1 = vec![("Tag1".to_string(), "Value1".to_string())];
    let tags2 = vec![("Tag2".to_string(), "Value2".to_string())];
    let tags3 = vec![("Tag3".to_string(), "Value3".to_string())];

    db_service
        .put_tags(TEST_ALLOWED_BUCKET, "testuser/file1.txt", tags1)
        .await
        .expect("Should store tags1");
    db_service
        .put_tags(TEST_ALLOWED_BUCKET, "testuser/file2.txt", tags2)
        .await
        .expect("Should store tags2");
    db_service
        .put_tags(TEST_ALLOWED_BUCKET, "testuser/file1.txt", tags3)
        .await
        .expect("Should store tags3");

    // Verify tags are isolated
    let retrieved1 = db_service
        .get_tags(TEST_ALLOWED_BUCKET, "testuser/file1.txt")
        .await
        .expect("Failed to get tags for file1");
    let retrieved2 = db_service
        .get_tags(TEST_ALLOWED_BUCKET, "testuser/file2.txt")
        .await
        .expect("Failed to get tags for file2");
    let retrieved3 = db_service
        .get_tags(TEST_ALLOWED_BUCKET, "testuser/file1.txt")
        .await
        .expect("Failed to get tags for file1");

    assert_eq!(retrieved1.len(), 1);
    assert_eq!(retrieved1[0].0, "Tag3");
    assert_eq!(retrieved2.len(), 1);
    assert_eq!(retrieved2[0].0, "Tag2");
    assert_eq!(retrieved3.len(), 1);
    assert_eq!(retrieved3[0].0, "Tag3");
}

#[tokio::test]
async fn test_delete_tags_idempotent() {
    let db_service = setup_test_db().await;

    // Delete tags for non-existent object (should succeed)
    let result = db_service
        .delete_tags(TEST_ALLOWED_BUCKET, "nonexistent.txt")
        .await;
    assert!(result.is_ok(), "Delete should be idempotent");

    // Delete again (should still succeed)
    let result2 = db_service
        .delete_tags(TEST_ALLOWED_BUCKET, "nonexistent.txt")
        .await;
    assert!(result2.is_ok(), "Delete should be idempotent");
}

#[tokio::test]
async fn test_special_characters_in_bucket_and_key() {
    let db_service = setup_test_db().await;

    let tags = vec![("Environment".to_string(), "Test".to_string())];

    // Test with special characters in bucket and key names
    let result = db_service
        .put_tags("bucket-with-dashes", "path/to/file.txt", tags.clone())
        .await;
    assert!(result.is_ok(), "Should handle dashes in bucket name");

    let retrieved = db_service
        .get_tags("bucket-with-dashes", "path/to/file.txt")
        .await
        .expect("Failed to get tags for bucket with dashes");
    assert_eq!(retrieved.len(), 1);
}

#[tokio::test]
async fn test_unicode_in_tags() {
    let db_service = setup_test_db().await;

    let tags = vec![
        ("Project".to_string(), "Crabcakes 🦀".to_string()),
        ("Description".to_string(), "测试".to_string()),
    ];

    let result = db_service
        .put_tags(TEST_ALLOWED_BUCKET, "file.txt", tags.clone())
        .await;
    assert!(result.is_ok(), "Should handle Unicode in tag values");

    let retrieved = db_service
        .get_tags(TEST_ALLOWED_BUCKET, "file.txt")
        .await
        .expect("Failed to get tags for unicode test");
    assert_eq!(retrieved.len(), 2);
    assert!(
        retrieved
            .iter()
            .any(|(k, v)| k == "Project" && v == "Crabcakes 🦀")
    );
    assert!(
        retrieved
            .iter()
            .any(|(k, v)| k == "Description" && v == "测试")
    );
}

#[tokio::test]
async fn test_migrations_run_on_initialization() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    // Initialize database first time
    let db1 = initialize_database(temp_dir.path())
        .await
        .expect("First initialization should succeed");
    drop(db1);

    // Initialize again (migrations should be idempotent)
    let db2 = initialize_database(temp_dir.path())
        .await
        .expect("Second initialization should succeed");
    drop(db2);

    // Database file should still exist and be valid
    let db_path = temp_dir.path().join("crabcakes.sqlite3");
    assert!(db_path.exists(), "Database should persist");
}
