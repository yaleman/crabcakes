use iam_rs::{Decision, IAMPolicy};
use tracing::debug;

use crate::{constants::S3Action, logging::setup_test_logging, policy::PolicyStore};
use std::path::PathBuf;

#[tokio::test]
async fn test_policy_loading() {
    let policy_store =
        PolicyStore::new(&PathBuf::from("test_config/policies")).expect("Failed to load policies");

    let count = policy_store.policy_count().await;
    assert!(count >= 1, "Expected at least 1 policy, got {}", count);
}

#[tokio::test]
async fn test_wildcard_principal() {
    setup_test_logging();

    let (_foo, policy_store) = PolicyStore::new_test();

    // inject a wildcard policy
    let allow_all_policy = r#"
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::bucket1"
            }
        ]
    }"#;
    policy_store
        .add_policy(
            "allow-all-bucket1",
            serde_json::from_str(allow_all_policy).expect("Failed to parse policy"),
        )
        .await
        .expect("Failed to add allow-all policy");

    // Create a simple request with anonymous principal
    let iam_request = iam_rs::IAMRequest::new(
        iam_rs::Principal::Wildcard,
        S3Action::ListBucket,
        iam_rs::Arn::parse("arn:aws:s3:::bucket1").expect("Failed to generate ARN"),
    );

    let result = policy_store.evaluate_request(&iam_request).await;
    // With the allow-all policy, wildcard principals should be allowed
    assert!(
        result.is_ok(),
        "Policy evaluation failed: {:?}",
        result.err()
    );
    assert_eq!(
        result.unwrap(),
        Decision::Allow,
        "Expected allow-all policy to allow wildcard access"
    );

    // Create a simple request with anonymous principal that should fail
    let iam_request = iam_rs::IAMRequest::new(
        iam_rs::Principal::Wildcard,
        S3Action::ListBucket,
        iam_rs::Arn::parse("arn:aws:s3:::bucket2").expect("Failed to generate ARN"),
    );
    let result = policy_store.evaluate_request(&iam_request).await;
    // With the allow-all policy, wildcard principals should be allowed
    assert!(
        result.is_ok(),
        "Policy evaluation failed: {:?}",
        result.err()
    );
    assert_eq!(
        result.unwrap(),
        Decision::Deny,
        "Expected allow-all policy to deny access"
    );
}

#[tokio::test]
async fn test_alice_policy() {
    setup_test_logging();
    let (_foo, policy_store) = PolicyStore::new_test();

    let policy: IAMPolicy = serde_json::from_str(
        r#"
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid"   : "AllowAliceGetObject",
                "Effect": "Allow",
                "Principal": {
                    "AWS":"arn:aws:iam:::user/alice"
                },
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket1/alice/*"
            }
        ]
    }"#,
    )
    .expect("Failed to parse alice policy");

    policy_store
        .add_policy("alice", policy)
        .await
        .expect("Failed to add alice policy");

    // Create a request from alice
    let iam_request = iam_rs::IAMRequest::new(
        iam_rs::Principal::Aws(iam_rs::PrincipalId::String(
            "arn:aws:iam:::user/alice".to_string(),
        )),
        S3Action::GetObject,
        iam_rs::Arn::parse("arn:aws:s3:::bucket1/alice/test.txt").unwrap(),
    );
    debug!("Evaluating request for alice: {:?}", iam_request);

    let policies = policy_store.policies().await;
    debug!("Policies loaded: {:?}", policies);

    let result = policy_store.evaluate_request(&iam_request).await;
    assert!(
        result.is_ok(),
        "Policy evaluation failed: {:?}",
        result.err()
    );
    assert_eq!(
        result.unwrap(),
        Decision::Allow,
        "Expected alice policy to allow alice's access"
    );
}
