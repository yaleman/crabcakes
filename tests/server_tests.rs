use std::fs;
use std::path::Path;
use tempfile::TempDir;
use tokio::time::{sleep, Duration};

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

#[tokio::test]
async fn test_list_buckets() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;

    // Test ListBuckets endpoint
    let response = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .expect("Failed to make request");

    assert_eq!(response.status(), 200);
    let body = response.text().await.expect("Failed to read response body");
    assert!(body.contains("<ListAllMyBucketsResult>"));
    assert!(body.contains("<Owner>"));
    assert!(body.contains("<Buckets>"));

    handle.abort();
}

#[tokio::test]
async fn test_list_objects() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;

    // Test ListObjectsV2 endpoint
    let response = reqwest::get(format!("http://127.0.0.1:{}/?list-type=2", port))
        .await
        .expect("Failed to make request");

    assert_eq!(response.status(), 200);
    let body = response.text().await.expect("Failed to read response body");
    assert!(body.contains("<ListBucketResult>"));
    assert!(body.contains("<Contents>"));
    assert!(body.contains("<Key>test.txt</Key>"));

    handle.abort();
}

#[tokio::test]
async fn test_head_object() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;

    // Test HeadObject endpoint
    let client = reqwest::Client::new();
    let response = client
        .head(format!("http://127.0.0.1:{}/test.txt", port))
        .send()
        .await
        .expect("Failed to make request");

    assert_eq!(response.status(), 200);
    assert!(response.headers().contains_key("content-length"));
    assert!(response.headers().contains_key("content-type"));
    assert!(response.headers().contains_key("etag"));
    assert!(response.headers().contains_key("last-modified"));

    let content_length = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .expect("Failed to parse content-length");
    assert_eq!(content_length, 29);

    handle.abort();
}

#[tokio::test]
async fn test_get_object() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;

    // Test GetObject endpoint
    let response = reqwest::get(format!("http://127.0.0.1:{}/test.txt", port))
        .await
        .expect("Failed to make request");

    assert_eq!(response.status(), 200);
    assert!(response.headers().contains_key("content-length"));
    assert!(response.headers().contains_key("content-type"));
    assert!(response.headers().contains_key("etag"));
    assert!(response.headers().contains_key("last-modified"));

    let body = response.text().await.expect("Failed to read response body");
    assert_eq!(body.trim(), "hello world this is test.txt");

    handle.abort();
}

#[tokio::test]
async fn test_get_nonexistent_object() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;

    // Test GetObject with nonexistent file
    let response = reqwest::get(format!("http://127.0.0.1:{}/nonexistent.txt", port))
        .await
        .expect("Failed to make request");

    assert_eq!(response.status(), 404);
    let body = response.text().await.expect("Failed to read response body");
    assert!(body.contains("<Error>"));
    assert!(body.contains("<Code>NoSuchKey</Code>"));

    handle.abort();
}

#[tokio::test]
async fn test_list_objects_with_prefix() {
    let temp_dir = setup_test_files();
    let (handle, port) = start_test_server(temp_dir.path()).await;

    // Test ListObjectsV2 with prefix filter
    let response = reqwest::get(format!(
        "http://127.0.0.1:{}/?list-type=2&prefix=test",
        port
    ))
    .await
    .expect("Failed to make request");

    assert_eq!(response.status(), 200);
    let body = response.text().await.expect("Failed to read response body");
    assert!(body.contains("<ListBucketResult>"));
    assert!(body.contains("<Prefix>test</Prefix>"));
    assert!(body.contains("<Key>test.txt</Key>"));

    handle.abort();
}