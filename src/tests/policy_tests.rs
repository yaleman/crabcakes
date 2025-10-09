use iam_rs::Decision;
use tracing::debug;

use crate::{constants::S3Action, policy::PolicyStore, setup_test_logging};
use std::path::PathBuf;

#[tokio::test]
async fn test_policy_loading() {
    let policy_store =
        PolicyStore::new(&PathBuf::from("test_config/policies")).expect("Failed to load policies");

    // Should have loaded both alice.json and allow-all.json
    let count = policy_store.policy_count().await;
    assert!(count >= 1, "Expected at least 1 policy, got {}", count);
}

#[tokio::test]
async fn test_wildcard_principal() {
    crate::setup_test_logging();

    let policy_store =
        PolicyStore::new(&PathBuf::from("test_config/policies")).expect("Failed to load policies");

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
}

#[tokio::test]
async fn test_alice_policy() {
    setup_test_logging();
    let policy_store =
        PolicyStore::new(&PathBuf::from("test_config/policies")).expect("Failed to load policies");

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
