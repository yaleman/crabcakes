use std::convert::Infallible;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, Response, StatusCode};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, warn};

use crate::filesystem::FilesystemService;
use crate::xml_responses::{ListBucketResponse, ListBucketsResponse};

pub struct S3Handler {
    filesystem: Arc<FilesystemService>,
}

impl S3Handler {
    pub fn new(filesystem: Arc<FilesystemService>) -> Self {
        Self { filesystem }
    }

    fn extract_bucket_name(&self, req: &Request<hyper::body::Incoming>) -> String {
        // Try to get bucket name from Host header (virtual-hosted style)
        // or fall back to a default
        req.headers()
            .get("Host")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.split('.').next())
            .unwrap_or("bucket")
            .to_string()
    }

    pub async fn handle_request(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();
        let bucket_name = self.extract_bucket_name(&req);

        info!(
            method = %method,
            path = %path,
            query = %query,
            bucket = %bucket_name,
            "Incoming S3 request"
        );

        // If list-type=2 is in the query, it's ALWAYS a ListBucket operation
        let is_list_operation = query.contains("list-type=2");

        // Parse path-style bucket requests: /bucket/ or /bucket/key
        let (is_bucket_operation, key) = self.parse_path(&path);
        let key = key.to_string();

        let response = match (&method, is_list_operation, is_bucket_operation, key.as_str(), query.as_str()) {
            // Any GET with list-type=2 is a ListBucket request
            (&Method::GET, true, _, _, query) => {
                debug!("Handling ListBucket request (list-type=2 query)");
                self.handle_list_bucket(query, &bucket_name, &path).await
            }
            // GET / - ListBuckets
            (&Method::GET, false, false, "", _) if path == "/" => {
                debug!("Handling ListBuckets request");
                self.handle_list_buckets(&bucket_name).await
            }
            // Path-style bucket root without query: GET /bucket/ or GET /bucket
            (&Method::GET, false, true, _, _) => {
                debug!("Handling ListBucket request (path-style, no query)");
                // Treat as ListBucket with default parameters
                self.handle_list_bucket("list-type=2", &bucket_name, &path)
                    .await
            }
            // HEAD /key or HEAD /bucket/key
            (&Method::HEAD, false, _, key, _) if !key.is_empty() => {
                debug!(key = %key, "Handling HeadObject request");
                self.handle_head_object(key).await
            }
            // GET /key or GET /bucket/key
            (&Method::GET, false, _, key, _) if !key.is_empty() => {
                debug!(key = %key, "Handling GetObject request");
                self.handle_get_object(key).await
            }
            // PUT /key or PUT /bucket/key
            (&Method::PUT, false, _, key, _) if !key.is_empty() => {
                debug!(key = %key, "Handling PutObject request");
                self.handle_put_object(req, key).await
            }
            _ => {
                warn!(method = %method, path = %path, "Unknown request pattern");
                self.not_found_response()
            }
        };

        let status = response.status();
        info!(status = %status.as_u16(), "Request completed");

        Ok(response)
    }

    /// Parse the path to determine if it's a bucket operation and extract the key
    /// Returns (is_bucket_operation, key)
    fn parse_path<'a>(&self, path: &'a str) -> (bool, &'a str) {
        let path = path.trim_start_matches('/');

        if path.is_empty() {
            // Root path: /
            return (false, "");
        }

        // Check if path has a file extension - if so, it's definitely a key
        if path.contains('.') && !path.ends_with('/') {
            return (false, path);
        }

        // Split on first slash to separate bucket from key
        if let Some(slash_pos) = path.find('/') {
            let key = &path[slash_pos + 1..];
            if key.is_empty() {
                // Path ends with slash: /bucket/
                (true, "")
            } else {
                // Path has key: /bucket/key
                (false, key)
            }
        } else {
            // No slash, no extension: /bucket (bucket operation)
            (true, "")
        }
    }

    async fn handle_list_bucket(
        &self,
        query: &str,
        bucket_name: &str,
        path: &str,
    ) -> Response<Full<Bytes>> {
        let mut prefix: Option<String> = None;
        let mut max_keys = 1000;
        let mut continuation_token = None;

        // Parse query parameters
        let mut query_prefix = None;
        for param in query.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                match key {
                    "prefix" => query_prefix = Some(value.to_string()),
                    "max-keys" => {
                        if let Ok(mk) = value.parse::<usize>() {
                            max_keys = mk.min(1000);
                        }
                    }
                    "continuation-token" => continuation_token = Some(value),
                    _ => {}
                }
            }
        }

        // Extract bucket name from path if present (path-style request)
        // e.g., /bucket1?list-type=2 or /bucket1/key?list-type=2
        let path_trimmed = path.trim_start_matches('/');
        let bucket_from_path = if !path_trimmed.is_empty() && path_trimmed != "/" {
            if let Some(slash_pos) = path_trimmed.find('/') {
                // Has a slash, extract bucket part
                Some(&path_trimmed[..slash_pos])
            } else {
                // No slash - could be bucket or file
                Some(path_trimmed)
            }
        } else {
            None
        };

        // Determine the prefix based on path and query
        if let Some(bucket) = bucket_from_path {
            if let Some(query_prefix) = query_prefix {
                // Combine bucket with query prefix: /bucket1?prefix=test.txt -> bucket1/test.txt
                prefix = Some(format!("{}/{}", bucket, query_prefix));
            } else {
                // No query prefix - check if path has more parts or looks like a file
                if let Some(slash_pos) = path_trimmed.find('/') {
                    // Path like /bucket1/test.txt -> prefix=bucket1/test.txt
                    let key_part = &path_trimmed[slash_pos + 1..];
                    if !key_part.is_empty() {
                        prefix = Some(format!("{}/{}", bucket, key_part));
                    } else {
                        // Just the bucket: /bucket1/ -> prefix=bucket1/
                        prefix = Some(format!("{}/", bucket));
                    }
                } else if bucket.contains('.') {
                    // Path like /test.txt (no slash, has dot) - treat as file prefix, not bucket
                    prefix = Some(bucket.to_string());
                } else {
                    // Path like /bucket1 (no slash, no dot) - treat as bucket
                    prefix = Some(format!("{}/", bucket));
                }
            }
        } else if let Some(query_prefix) = query_prefix {
            // No bucket in path, just use query prefix as-is
            // e.g., /?list-type=2&prefix=test -> prefix=test
            prefix = Some(query_prefix);
        }

        match self
            .filesystem
            .list_directory(prefix.as_deref(), max_keys, continuation_token)
        {
            Ok((entries, next_token)) => {
                debug!(
                    count = entries.len(),
                    has_more = next_token.is_some(),
                    "Listed directory entries"
                );
                let response = ListBucketResponse::new(
                    bucket_name.to_string(),
                    prefix.unwrap_or_default(),
                    max_keys,
                    entries,
                    next_token,
                );

                match response.to_xml() {
                    Ok(xml) => Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/xml")
                        .header("Content-Length", xml.len())
                        .body(Full::new(Bytes::from(xml)))
                        .unwrap(),
                    Err(e) => {
                        error!(error = %e, "Failed to serialize ListBucket response");
                        self.internal_error_response()
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to list directory");
                self.internal_error_response()
            }
        }
    }

    async fn handle_list_buckets(&self, _bucket_name: &str) -> Response<Full<Bytes>> {
        // List all top-level directories as buckets
        match self.filesystem.list_buckets() {
            Ok(buckets) => {
                debug!(count = buckets.len(), "Listed buckets");
                let response = ListBucketsResponse::from_buckets(buckets);

                match response.to_xml() {
                    Ok(xml) => Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/xml")
                        .header("Content-Length", xml.len())
                        .body(Full::new(Bytes::from(xml)))
                        .unwrap(),
                    Err(e) => {
                        error!(error = %e, "Failed to serialize ListBuckets response");
                        self.internal_error_response()
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to list buckets");
                self.internal_error_response()
            }
        }
    }

    async fn handle_head_object(&self, key: &str) -> Response<Full<Bytes>> {
        match self.filesystem.get_file_metadata(key) {
            Ok(metadata) => {
                debug!(key = %key, size = metadata.size, "HeadObject success");
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", metadata.content_type)
                    .header("Content-Length", metadata.size)
                    .header(
                        "Last-Modified",
                        metadata
                            .last_modified
                            .format("%a, %d %b %Y %H:%M:%S GMT")
                            .to_string(),
                    )
                    .header("ETag", metadata.etag)
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }
            Err(e) => {
                warn!(key = %key, error = %e, "HeadObject failed: file not found");
                self.not_found_response()
            }
        }
    }

    async fn handle_get_object(&self, key: &str) -> Response<Full<Bytes>> {
        match self.filesystem.get_file_metadata(key) {
            Ok(metadata) => match File::open(&metadata.path).await {
                Ok(mut file) => {
                    let mut contents = Vec::new();
                    match file.read_to_end(&mut contents).await {
                        Ok(bytes_read) => {
                            debug!(key = %key, size = bytes_read, "GetObject success");
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("Content-Type", metadata.content_type)
                                .header("Content-Length", metadata.size)
                                .header(
                                    "Last-Modified",
                                    metadata
                                        .last_modified
                                        .format("%a, %d %b %Y %H:%M:%S GMT")
                                        .to_string(),
                                )
                                .header("ETag", metadata.etag)
                                .body(Full::new(Bytes::from(contents)))
                                .unwrap()
                        }
                        Err(e) => {
                            error!(key = %key, error = %e, "Failed to read file contents");
                            self.internal_error_response()
                        }
                    }
                }
                Err(e) => {
                    error!(key = %key, error = %e, "Failed to open file");
                    self.not_found_response()
                }
            },
            Err(e) => {
                warn!(key = %key, error = %e, "GetObject failed: file not found");
                self.not_found_response()
            }
        }
    }

    async fn handle_put_object(
        &self,
        req: Request<hyper::body::Incoming>,
        key: &str,
    ) -> Response<Full<Bytes>> {
        // Read the request body
        let body = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                error!(key = %key, error = %e, "Failed to read request body");
                return self.internal_error_response();
            }
        };

        // Write the file
        match self.filesystem.write_file(key, &body).await {
            Ok(metadata) => {
                debug!(key = %key, size = metadata.size, "PutObject success");
                Response::builder()
                    .status(StatusCode::OK)
                    .header("ETag", metadata.etag)
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }
            Err(e) => {
                error!(key = %key, error = %e, "Failed to write file");
                self.internal_error_response()
            }
        }
    }

    fn not_found_response(&self) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/xml")
            .body(Full::new(Bytes::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>",
            )))
            .unwrap()
    }

    fn internal_error_response(&self) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("Content-Type", "application/xml")
            .body(Full::new(Bytes::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>InternalError</Code><Message>We encountered an internal error. Please try again.</Message></Error>",
            )))
            .unwrap()
    }
}
