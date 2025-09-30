use std::fs;
use std::path::Path;
use tempfile::TempDir;
use tokio::time::{sleep, Duration};

use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::Client;

use crabcakes::server::Server;

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
    // Copy testfiles directory directly (includes bucket1/ and bucket2/ subdirs)
    copy_dir_all("testfiles", temp_dir.path()).expect("Failed to copy test files");
    temp_dir
}

async fn start_test_server(temp_dir: &Path) -> (tokio::task::JoinHandle<()>, u16) {
    let (server, port) = Server::test_mode(temp_dir.to_path_buf())
        .await
        .expect("Failed to create test server");

    let handle = tokio::spawn(async move {
        if let Err(e) = server.run().await {
            eprintln!("Server error: {}", e);
        }
    });

    // Give the server time to start
    sleep(Duration::from_millis(100)).await;

    (handle, port)
}

async fn create_s3_client(port: u16) -> Client {
    let creds = Credentials::new("test", "test", None, None, "test");
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(creds)
        .region(Region::new("us-east-1"))
        .load()
        .await;

    let s3_config = aws_sdk_s3::config::Builder::from(&config)
        .endpoint_url(format!("http://127.0.0.1:{}", port))
        .force_path_style(true)
        .build();

    Client::from_conf(s3_config)
}

#[tokio::test]
async fn test_list_buckets() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;
    let client = create_s3_client(port).await;

    let result = client.list_buckets().send().await;
    assert!(result.is_ok(), "ListBuckets failed: {:?}", result.err());

    let output = result.unwrap();
    let buckets = output.buckets();
    assert!(!buckets.is_empty(), "No buckets found");

    // Verify both bucket1 and bucket2 are listed
    let bucket_names: Vec<_> = buckets.iter().filter_map(|b| b.name()).collect();
    assert!(
        bucket_names.contains(&"bucket1"),
        "Expected bucket1 in listing"
    );
    assert!(
        bucket_names.contains(&"bucket2"),
        "Expected bucket2 in listing"
    );

    handle.abort();
}

#[tokio::test]
async fn test_list_objects() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;
    let client = create_s3_client(port).await;

    let result = client.list_objects_v2().bucket("bucket1").send().await;
    assert!(result.is_ok(), "ListObjectsV2 failed: {:?}", result.err());

    let output = result.unwrap();
    let contents = output.contents();
    assert!(!contents.is_empty());
    assert!(
        contents.iter().any(|obj| obj.key() == Some("bucket1/test.txt")),
        "Expected to find bucket1/test.txt in listing"
    );

    handle.abort();
}

#[tokio::test]
async fn test_head_object() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;
    let client = create_s3_client(port).await;

    let result = client
        .head_object()
        .bucket("bucket1")
        .key("test.txt")
        .send()
        .await;
    assert!(result.is_ok(), "HeadObject failed: {:?}", result.err());

    let output = result.unwrap();
    assert_eq!(output.content_length(), Some(29));
    assert!(output.content_type().is_some());
    assert!(output.e_tag().is_some());
    assert!(output.last_modified().is_some());

    handle.abort();
}

#[tokio::test]
async fn test_get_object() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;
    let client = create_s3_client(port).await;

    let result = client
        .get_object()
        .bucket("bucket1")
        .key("test.txt")
        .send()
        .await;
    assert!(result.is_ok(), "GetObject failed: {:?}", result.err());

    let output = result.unwrap();
    assert_eq!(output.content_length(), Some(29));
    assert!(output.content_type().is_some());
    assert!(output.e_tag().is_some());
    assert!(output.last_modified().is_some());

    let body = output.body.collect().await.unwrap().into_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert_eq!(body_str.trim(), "hello world this is test.txt");

    handle.abort();
}

#[tokio::test]
async fn test_get_nonexistent_object() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;
    let client = create_s3_client(port).await;

    let result = client
        .get_object()
        .bucket("bucket1")
        .key("nonexistent.txt")
        .send()
        .await;
    assert!(result.is_err(), "Expected error for nonexistent object");

    handle.abort();
}

#[tokio::test]
async fn test_list_objects_with_prefix() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;
    let client = create_s3_client(port).await;

    let result = client
        .list_objects_v2()
        .bucket("bucket1")
        .prefix("test")
        .send()
        .await;
    assert!(
        result.is_ok(),
        "ListObjectsV2 with prefix failed: {:?}",
        result.err()
    );

    let output = result.unwrap();
    let contents = output.contents();
    assert!(!contents.is_empty());
    assert!(
        contents.iter().any(|obj| obj.key() == Some("bucket1/test.txt")),
        "Expected to find bucket1/test.txt in listing"
    );

    handle.abort();
}

#[tokio::test]
async fn test_path_style_bucket_listing() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;
    let client = create_s3_client(port).await;

    let result = client.list_objects_v2().bucket("bucket1").send().await;
    assert!(result.is_ok(), "ListObjectsV2 failed: {:?}", result.err());

    let output = result.unwrap();
    assert!(!output.contents().is_empty());

    handle.abort();
}

#[tokio::test]
async fn test_list_with_file_prefix() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;
    let client = create_s3_client(port).await;

    let result = client
        .list_objects_v2()
        .bucket("bucket1")
        .prefix("test.txt")
        .send()
        .await;
    assert!(
        result.is_ok(),
        "ListObjectsV2 with file prefix failed: {:?}",
        result.err()
    );

    let output = result.unwrap();
    assert_eq!(output.prefix(), Some("bucket1/test.txt"));
    let contents = output.contents();
    assert!(!contents.is_empty());
    assert!(
        contents.iter().any(|obj| obj.key() == Some("bucket1/test.txt")),
        "Expected to find bucket1/test.txt in listing"
    );

    handle.abort();
}

#[tokio::test]
async fn test_bucket2_json_file() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;
    let client = create_s3_client(port).await;

    // Test HeadObject on bucket2/hello-world.json
    let head_result = client
        .head_object()
        .bucket("bucket2")
        .key("hello-world.json")
        .send()
        .await;
    assert!(
        head_result.is_ok(),
        "HeadObject on bucket2/hello-world.json failed: {:?}",
        head_result.err()
    );

    let head_output = head_result.unwrap();
    assert_eq!(head_output.content_length(), Some(37));
    assert_eq!(head_output.content_type(), Some("application/json"));

    // Test GetObject on bucket2/hello-world.json
    let get_result = client
        .get_object()
        .bucket("bucket2")
        .key("hello-world.json")
        .send()
        .await;
    assert!(
        get_result.is_ok(),
        "GetObject on bucket2/hello-world.json failed: {:?}",
        get_result.err()
    );

    let get_output = get_result.unwrap();
    let body = get_output.body.collect().await.unwrap().into_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("hello world"), "Expected JSON content");

    handle.abort();
}

#[tokio::test]
async fn test_put_object() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;
    let client = create_s3_client(port).await;

    let test_content = b"This is a test file uploaded via PutObject";
    let test_key = "uploaded-file.txt";

    // Test PutObject
    let put_result = client
        .put_object()
        .bucket("bucket1")
        .key(test_key)
        .body(test_content.to_vec().into())
        .send()
        .await;
    assert!(
        put_result.is_ok(),
        "PutObject failed: {:?}",
        put_result.err()
    );

    let put_output = put_result.unwrap();
    assert!(put_output.e_tag().is_some(), "Expected ETag in response");

    // Verify we can retrieve the uploaded file
    let get_result = client
        .get_object()
        .bucket("bucket1")
        .key(test_key)
        .send()
        .await;
    assert!(
        get_result.is_ok(),
        "GetObject after PutObject failed: {:?}",
        get_result.err()
    );

    let get_output = get_result.unwrap();
    assert_eq!(get_output.content_length(), Some(test_content.len() as i64));
    assert_eq!(get_output.content_type(), Some("text/plain"));

    let body = get_output.body.collect().await.unwrap().into_bytes();
    assert_eq!(body.as_ref(), test_content);

    // Verify HeadObject works
    let head_result = client
        .head_object()
        .bucket("bucket1")
        .key(test_key)
        .send()
        .await;
    assert!(
        head_result.is_ok(),
        "HeadObject after PutObject failed: {:?}",
        head_result.err()
    );

    let head_output = head_result.unwrap();
    assert_eq!(head_output.content_length(), Some(test_content.len() as i64));
    assert_eq!(head_output.content_type(), Some("text/plain"));

    handle.abort();
}