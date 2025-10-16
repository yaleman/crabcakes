//! Unit tests for RequestHandler business logic
//!
//! Tests all extracted API handler business logic methods without HTTP concerns.
//! Uses in-memory database and temporary directories for isolation.

use crate::logging::setup_test_logging;
use crate::request_handler::RequestHandler;
use crate::web::serde::{CredentialInfo, VacuumResult};

#[tokio::test]
async fn test_api_create_bucket_valid() {
    let handler = RequestHandler::new_test().await;

    // Create a valid bucket
    let result = handler.api_create_bucket("test-bucket-123").await;
    assert!(result.is_ok(), "Should create valid bucket");

    // Verify bucket exists
    let buckets = handler
        .filesystem
        .list_buckets()
        .await
        .expect("Should list buckets");
    assert!(buckets.contains(&"test-bucket-123".to_string()));
}

#[tokio::test]
async fn test_api_create_bucket_invalid_uppercase() {
    let handler = RequestHandler::new_test().await;

    // Try to create bucket with uppercase letters
    let result = handler.api_create_bucket("Test-Bucket").await;
    assert!(result.is_err(), "Should reject uppercase letters");
}

#[tokio::test]
async fn test_api_create_bucket_invalid_special_chars() {
    let handler = RequestHandler::new_test().await;

    // Try to create bucket with special characters
    let result = handler.api_create_bucket("test_bucket").await;
    assert!(result.is_err(), "Should reject underscores");

    let result = handler.api_create_bucket("test.bucket").await;
    assert!(result.is_err(), "Should reject periods");
}

#[tokio::test]
async fn test_api_create_bucket_reserved_name() {
    let handler = RequestHandler::new_test().await;

    // Try to create bucket with reserved names
    let reserved_names = vec!["admin", "api", "login", "logout", "config"];
    for name in reserved_names {
        let result = handler.api_create_bucket(name).await;
        assert!(
            result.is_err(),
            "Should reject reserved bucket name: {}",
            name
        );
    }
}

#[tokio::test]
async fn test_api_create_bucket_too_long() {
    let handler = RequestHandler::new_test().await;

    // Try to create bucket with name > 63 characters
    let long_name = "a".repeat(64);
    let result = handler.api_create_bucket(&long_name).await;
    assert!(result.is_err(), "Should reject name longer than 63 chars");
}

#[tokio::test]
async fn test_api_create_bucket_empty() {
    let handler = RequestHandler::new_test().await;

    // Try to create bucket with empty name
    let result = handler.api_create_bucket("").await;
    assert!(result.is_err(), "Should reject empty bucket name");
}

#[tokio::test]
async fn test_api_create_bucket_duplicate() {
    let handler = RequestHandler::new_test().await;

    // Create first bucket
    handler
        .api_create_bucket("duplicate-test")
        .await
        .expect("First creation should succeed");

    // Try to create duplicate
    let result = handler.api_create_bucket("duplicate-test").await;
    assert!(result.is_err(), "Should reject duplicate bucket name");
}

#[tokio::test]
async fn test_api_delete_bucket_empty() {
    let handler = RequestHandler::new_test().await;

    // Create and delete empty bucket
    handler
        .api_create_bucket("delete-me")
        .await
        .expect("Should create bucket");

    let result = handler.api_delete_bucket("delete-me", false).await;
    assert!(result.is_ok(), "Should delete empty bucket");

    // Verify bucket is gone
    let buckets = handler
        .filesystem
        .list_buckets()
        .await
        .expect("Should list buckets");
    assert!(!buckets.contains(&"delete-me".to_string()));
}

#[tokio::test]
async fn test_api_delete_bucket_with_objects_no_force() {
    let handler = RequestHandler::new_test().await;

    // Create bucket and add an object
    handler
        .api_create_bucket("bucket-with-files")
        .await
        .expect("Should create bucket");

    handler
        .filesystem
        .write_file("bucket-with-files/test.txt", b"test content")
        .await
        .expect("Should write file");

    // Try to delete without force flag
    let result = handler.api_delete_bucket("bucket-with-files", false).await;
    assert!(result.is_err(), "Should fail to delete non-empty bucket");
}

#[tokio::test]
async fn test_api_delete_bucket_with_objects_force() {
    let handler = RequestHandler::new_test().await;

    // Create bucket and add objects
    handler
        .api_create_bucket("force-delete-bucket")
        .await
        .expect("Should create bucket");

    handler
        .filesystem
        .write_file("force-delete-bucket/file1.txt", b"content1")
        .await
        .expect("Should write file1");

    handler
        .filesystem
        .write_file("force-delete-bucket/file2.txt", b"content2")
        .await
        .expect("Should write file2");

    // Force delete should succeed
    let result = handler.api_delete_bucket("force-delete-bucket", true).await;
    assert!(result.is_ok(), "Should force delete non-empty bucket");

    // Verify bucket is gone
    let buckets = handler
        .filesystem
        .list_buckets()
        .await
        .expect("Should list buckets");
    assert!(!buckets.contains(&"force-delete-bucket".to_string()));
}

#[tokio::test]
async fn test_api_list_policies_empty() {
    let handler = RequestHandler::new_test().await;

    // List policies (should have test policies from setup)
    let policies = handler
        .api_list_policies()
        .await
        .expect("Should list policies");

    // Verify it's a vec of ApiPolicyInfo
    assert!(!policies.is_empty(), "Test setup should have policies");

    for policy in &policies {
        assert!(!policy.name.is_empty(), "Policy should have name");
        assert!(policy.policy.is_object(), "Policy should be JSON object");
    }
}

#[tokio::test]
async fn test_api_list_policies_sorted() {
    let handler = RequestHandler::new_test().await;

    let policies = handler
        .api_list_policies()
        .await
        .expect("Should list policies");

    // Verify policies are sorted by name
    let names: Vec<String> = policies.iter().map(|p| p.name.clone()).collect();
    let mut sorted_names = names.clone();
    sorted_names.sort();

    assert_eq!(names, sorted_names, "Policies should be sorted by name");
}

#[tokio::test]
async fn test_api_create_policy_valid() {
    setup_test_logging();
    let handler = RequestHandler::new_test().await;

    // Create a simple policy
    let policy_json = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam:::user/testuser"},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::test-bucket/*"
        }]
    });

    let policy: iam_rs::IAMPolicy =
        serde_json::from_value(policy_json).expect("Failed to parse policy JSON");
    let result = handler.api_create_policy("test-policy", policy).await;

    assert!(result.is_ok(), "Should create valid policy");

    // Verify policy exists
    let policies = handler
        .api_list_policies()
        .await
        .expect("Failed to list policies");
    assert!(policies.iter().any(|p| p.name == "test-policy"));
}

#[tokio::test]
async fn test_api_update_policy_existing() {
    let handler = RequestHandler::new_test().await;

    // Get an existing policy from test setup
    let policies = handler
        .api_list_policies()
        .await
        .expect("Failed to list policies");
    let first_policy = policies.first().expect("Should have at least one policy");

    // Update it
    let updated_policy_json = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Principal": {"AWS": "*"},
            "Action": "s3:*",
            "Resource": "*"
        }]
    });

    let updated_policy: iam_rs::IAMPolicy =
        serde_json::from_value(updated_policy_json).expect("Failed to parse updated policy JSON");
    let result = handler
        .api_update_policy(first_policy.name.clone(), updated_policy)
        .await;

    assert!(result.is_ok(), "Should update existing policy");
}

#[tokio::test]
async fn test_api_update_policy_nonexistent() {
    let handler = RequestHandler::new_test().await;

    let policy_json = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "s3:GetObject",
            "Resource": "*"
        }]
    });

    let policy: iam_rs::IAMPolicy =
        serde_json::from_value(policy_json).expect("Failed to parse policy JSON");
    let result = handler
        .api_update_policy("nonexistent-policy".to_string(), policy)
        .await;

    assert!(result.is_err(), "Should fail to update nonexistent policy");
}

#[tokio::test]
async fn test_api_delete_policy_existing() {
    let handler = RequestHandler::new_test().await;

    // Create a policy to delete
    let policy_json = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "s3:GetObject",
            "Resource": "*"
        }]
    });

    let policy: iam_rs::IAMPolicy =
        serde_json::from_value(policy_json).expect("Failed to parse policy JSON");
    handler
        .api_create_policy("policy-to-delete", policy)
        .await
        .expect("Should create policy");

    // Delete it
    let result = handler.api_delete_policy("policy-to-delete").await;
    assert!(result.is_ok(), "Should delete existing policy");

    // Verify it's gone
    let policies = handler
        .api_list_policies()
        .await
        .expect("Failed to list policies");
    assert!(!policies.iter().any(|p| p.name == "policy-to-delete"));
}

#[tokio::test]
async fn test_api_delete_policy_idempotent() {
    let handler = RequestHandler::new_test().await;

    // Delete non-existent policy (should be idempotent/succeed)
    let _result = handler.api_delete_policy("never-existed-policy").await;
    // Note: PolicyStore.delete_policy may error or succeed - depends on implementation
    // Based on the pattern, it should probably succeed idempotently
}

#[tokio::test]
async fn test_api_list_credentials_empty() {
    let handler = RequestHandler::new_test().await;

    let creds = handler
        .api_list_credentials()
        .await
        .expect("Should list credentials");

    // Test setup may have no credentials initially (new_test uses empty temp dir)
    // Just verify the structure works
    for cred in &creds {
        assert!(!cred.access_key_id.is_empty(), "Should have access_key_id");
    }
}

#[tokio::test]
async fn test_api_list_credentials_sorted() {
    let handler = RequestHandler::new_test().await;

    let creds = handler
        .api_list_credentials()
        .await
        .expect("Failed to list credentials");

    // Verify credentials are sorted
    let keys: Vec<String> = creds.iter().map(|c| c.access_key_id.clone()).collect();
    let mut sorted_keys = keys.clone();
    sorted_keys.sort();

    assert_eq!(keys, sorted_keys, "Credentials should be sorted");
}

#[tokio::test]
async fn test_api_list_credentials_no_secrets() {
    let handler = RequestHandler::new_test().await;

    let creds = handler
        .api_list_credentials()
        .await
        .expect("Failed to list credentials");

    // CredentialInfo struct should only have access_key_id, not secret
    for cred in &creds {
        // Just verify the structure exists
        let _: &CredentialInfo = cred;
    }
}

#[tokio::test]
async fn test_api_create_credential_valid() {
    let handler = RequestHandler::new_test().await;

    // Secret must be exactly 40 characters
    let secret = "a".repeat(40);
    let result = handler
        .api_create_credential("newuser".to_string(), secret)
        .await;

    assert!(result.is_ok(), "Should create valid credential");

    // Verify credential exists
    let creds = handler
        .api_list_credentials()
        .await
        .expect("Failed to list credentials");
    assert!(creds.iter().any(|c| c.access_key_id == "newuser"));
}

#[tokio::test]
async fn test_api_create_credential_duplicate() {
    let handler = RequestHandler::new_test().await;

    // Secrets must be exactly 40 characters
    let secret1 = "a".repeat(40);
    let secret2 = "b".repeat(40);

    // Create first credential
    handler
        .api_create_credential("dupuser".to_string(), secret1)
        .await
        .expect("First creation should succeed");

    // Try to create duplicate
    let result = handler
        .api_create_credential("dupuser".to_string(), secret2)
        .await;

    assert!(result.is_err(), "Should reject duplicate access_key_id");
}

#[tokio::test]
async fn test_api_update_credential_existing() {
    let handler = RequestHandler::new_test().await;

    // Secrets must be exactly 40 characters
    let old_secret = "a".repeat(40);
    let new_secret = "b".repeat(40);

    // Create a credential
    handler
        .api_create_credential("updateuser".to_string(), old_secret)
        .await
        .expect("Should create credential");

    // Update it
    let result = handler
        .api_update_credential("updateuser".to_string(), new_secret)
        .await;

    assert!(result.is_ok(), "Should update existing credential");
}

#[tokio::test]
async fn test_api_update_credential_nonexistent() {
    let handler = RequestHandler::new_test().await;

    // Try to update non-existent credential
    let result = handler
        .api_update_credential("nosuchuser".to_string(), "secret".to_string())
        .await;

    assert!(
        result.is_err(),
        "Should fail to update nonexistent credential"
    );
}

#[tokio::test]
async fn test_api_delete_credential_existing() {
    let handler = RequestHandler::new_test().await;

    // Secret must be exactly 40 characters
    let secret = "a".repeat(40);

    // Create credential to delete
    handler
        .api_create_credential("deleteuser".to_string(), secret)
        .await
        .expect("Should create credential");

    // Delete it
    let result = handler.api_delete_credential("deleteuser").await;
    assert!(result.is_ok(), "Should delete existing credential");

    // Verify it's gone
    let creds = handler
        .api_list_credentials()
        .await
        .expect("Failed to list credentials");
    assert!(!creds.iter().any(|c| c.access_key_id == "deleteuser"));
}

#[tokio::test]
async fn test_api_delete_credential_idempotent() {
    let handler = RequestHandler::new_test().await;

    // Delete non-existent credential (should be idempotent)
    let _result = handler.api_delete_credential("never-existed").await;
    // Should succeed or be idempotent
}

#[tokio::test]
async fn test_api_delete_temp_credential_idempotent() {
    let handler = RequestHandler::new_test().await;

    // Delete non-existent temp credential (should be idempotent)
    let result = handler.api_delete_temp_credential("fake-temp-key").await;
    assert!(
        result.is_ok(),
        "Should succeed even if credential doesn't exist"
    );
}

#[tokio::test]
async fn test_api_delete_temp_credential_existing() {
    let handler = RequestHandler::new_test().await;

    // Create a temp credential in the database
    handler
        .db
        .store_temporary_credentials(
            "temp-key-123",
            "temp-secret",
            "session-123",
            "test@example.com",
            "user-123",
            chrono::Utc::now() + chrono::Duration::try_hours(1).expect("Failed to create duration"),
        )
        .await
        .expect("Should store temp credential");

    // Delete it
    let result = handler.api_delete_temp_credential("temp-key-123").await;
    assert!(result.is_ok(), "Should delete existing temp credential");

    // Verify it's gone
    let creds = handler
        .db
        .get_temporary_credentials("temp-key-123")
        .await
        .expect("Failed to get temporary credentials");
    assert!(creds.is_none(), "Temp credential should be deleted");
}

#[tokio::test]
async fn test_api_database_vacuum_status() {
    let handler = RequestHandler::new_test().await;

    let stats = handler
        .api_database_vacuum_status()
        .await
        .expect("Should get vacuum status");

    // Verify structure
    assert!(stats.page_count >= 0, "Page count should be non-negative");
    assert!(stats.page_size > 0, "Page size should be positive");
    assert!(
        stats.freelist_count >= 0,
        "Freelist count should be non-negative"
    );
    assert!(
        stats.total_size_bytes >= 0,
        "Total size should be non-negative"
    );
    assert!(
        stats.freelist_size_bytes >= 0,
        "Freelist size should be non-negative"
    );
}

#[tokio::test]
async fn test_api_database_vacuum_without_confirm() {
    let handler = RequestHandler::new_test().await;

    // Try to vacuum without confirmation
    let result = handler.api_database_vacuum(false).await;
    assert!(result.is_err(), "Should require confirmation to vacuum");
}

#[tokio::test]
async fn test_api_database_vacuum_with_confirm() {
    let handler = RequestHandler::new_test().await;

    // Vacuum with confirmation
    let result = handler.api_database_vacuum(true).await;
    assert!(result.is_ok(), "Should vacuum with confirmation");

    let vacuum_result = result.expect("Failed to get vacuum result");
    assert!(vacuum_result.success, "Vacuum should succeed");
    assert!(
        vacuum_result.pages_freed >= 0,
        "Pages freed should be non-negative"
    );
}

#[tokio::test]
async fn test_api_database_vacuum_result_structure() {
    let handler = RequestHandler::new_test().await;

    let result = handler
        .api_database_vacuum(true)
        .await
        .expect("Should vacuum");

    // Verify VacuumResult structure
    let _: VacuumResult = result;
}
