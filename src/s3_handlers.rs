use std::convert::Infallible;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Method, Request, Response, StatusCode};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, warn};

use crate::auth::{AuthContext, extract_bucket_and_key, http_method_to_s3_action, verify_sigv4};
use crate::body_buffer::BufferedBody;
use crate::credentials::CredentialStore;
use crate::filesystem::FilesystemService;
use crate::policy::PolicyStore;
use crate::xml_responses::{
    CopyObjectResponse, DeleteError, DeleteRequest, DeleteResponse, DeletedObject,
    GetBucketLocationResponse, ListBucketResponse, ListBucketV1Response, ListBucketsResponse,
};

pub struct S3Handler {
    server_addr: String,
    filesystem: Arc<FilesystemService>,
    policy_store: Arc<PolicyStore>,
    credentials_store: Arc<CredentialStore>,
    region: String,
    require_signature: bool,
}

impl S3Handler {
    pub fn new(
        filesystem: Arc<FilesystemService>,
        policy_store: Arc<PolicyStore>,
        credentials_store: Arc<CredentialStore>,
        region: String,
        require_signature: bool,
        server_addr: String,
    ) -> Self {
        Self {
            filesystem,
            policy_store,
            credentials_store,
            region,
            require_signature,
            server_addr,
        }
    }

    /// Verify AWS Signature V4 and buffer the request body
    /// Returns Ok with (authenticated_username, buffered_body, request_parts) or Err with error response
    async fn verify_and_buffer_request(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<(Option<String>, BufferedBody, http::request::Parts), Response<Full<Bytes>>> {
        // Extract the parts we need before consuming the request
        let (parts, body) = req.into_parts();

        // Buffer the body (memory or disk depending on size)
        let buffered_body = match BufferedBody::from_incoming(body).await {
            Ok(body) => body,
            Err(e) => {
                error!(error = %e, "Failed to buffer request body");
                return Err(self.internal_error_response());
            }
        };

        // Get the body as Vec<u8> for signature verification
        let body_vec = match buffered_body.to_vec().await {
            Ok(vec) => vec,
            Err(e) => {
                error!(error = %e, "Failed to read buffered body");
                return Err(self.internal_error_response());
            }
        };

        // If signature verification is not required, allow the request
        if !self.require_signature {
            debug!("Signature verification not required, allowing request");
            // Recreate BufferedBody from vec for later use
            return Ok((None, BufferedBody::Memory(body_vec), parts));
        }

        // Reconstruct the request with the buffered body for verification
        let http_request = http::Request::from_parts(parts.clone(), body_vec.clone());

        // Verify the signature
        match verify_sigv4(
            http_request,
            self.credentials_store.clone(),
            &self.region,
            self.require_signature,
        )
        .await
        {
            Ok(verified) => {
                info!(
                    access_key = %verified.access_key_id,
                    "Request signature verified successfully"
                );
                // Recreate BufferedBody from vec for later use
                Ok((
                    Some(verified.access_key_id),
                    BufferedBody::Memory(body_vec),
                    parts,
                ))
            }
            Err(e) => {
                warn!(error = %e, "Signature verification failed");
                Err(self.unauthorized_response(&format!("Signature verification failed: {}", e)))
            }
        }
    }

    pub async fn handle_request(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        // Verify signature and buffer body (or return error response)
        let (authenticated_username, buffered_body, parts) =
            match self.verify_and_buffer_request(req).await {
                Ok(result) => result,
                Err(response) => return Ok(response),
            };

        // Extract request metadata from parts
        let method = parts.method.clone();
        let path = parts.uri.path().to_string();
        let query = parts.uri.query().unwrap_or("").to_string();
        let mut bucket_name: String = String::new();

        if let Some(host_header) = parts.headers.get("Host") {
            let host_header = match host_header.to_str() {
                Ok(header) => header.to_string(),
                Err(_) => return Ok(self.internal_error_response()),
            };
            if host_header.ends_with(&format!(".{}", self.server_addr)) {
                bucket_name = host_header
                    .strip_suffix(&format!(".{}", self.server_addr))
                    .map(|s| s.to_string())
                    .unwrap_or_default();
            }
        }

        // Check for x-amz-copy-source header to detect CopyObject operation
        let copy_source = parts
            .headers
            .get("x-amz-copy-source")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        info!(
            method = %method,
            path = %path,
            query = %query,
            bucket = %bucket_name,
            authenticated_user = ?authenticated_username,
            copy_source = ?copy_source,
            "Incoming S3 request"
        );

        // Build authentication context from verified request
        let auth_context = if let Some(ref username) = authenticated_username {
            // Use verified username to build principal
            let arn = format!("arn:aws:iam:::user/{}", username);
            AuthContext {
                principal: iam_rs::Principal::Aws(iam_rs::PrincipalId::String(arn)),
                username: Some(username.clone()),
            }
        } else {
            // Fallback to anonymous if signature not required
            AuthContext {
                principal: iam_rs::Principal::Wildcard,
                username: None,
            }
        };

        // Parse path-style bucket requests: /bucket/ or /bucket/key
        let (is_bucket_operation, key) = self.parse_path(&path);
        let key = key.to_string();

        // Determine S3 action and resource for authorization
        let s3_action =
            http_method_to_s3_action(method.as_str(), &path, &query, is_bucket_operation);
        let (bucket, extracted_key) = extract_bucket_and_key(&path);

        // Use extracted bucket from path for path-style requests, fall back to host header
        let bucket_for_operation = match bucket.as_ref() {
            Some(val) => val.as_str(),
            None => {
                debug!(path=%path, "No bucket in path, using bucket from Host header if available");
                bucket_name.as_str()
            }
        };

        // Build IAM request and evaluate policy
        let iam_request = match auth_context.build_iam_request(
            s3_action,
            bucket.as_deref(),
            extracted_key.as_deref(),
        ) {
            Ok(req) => req,
            Err(e) => {
                error!(error = %e, "Failed to build IAM request");
                return Ok(self.internal_error_response());
            }
        };

        match self.policy_store.evaluate_request(&iam_request).await {
            Ok(true) => {
                debug!("Authorization granted");
            }
            Ok(false) => {
                warn!(
                    principal = ?iam_request.principal,
                    action = %s3_action,
                    "Authorization denied"
                );
                return Ok(self.access_denied_response());
            }
            Err(e) => {
                error!(error = %e, "Error evaluating policy");
                return Ok(self.internal_error_response());
            }
        }

        // Determine if this is a V2 list operation (has list-type=2)
        let is_list_v2_operation = query.contains("list-type=2");

        // Detect if this is a V1 list operation (bucket-level GET with certain query params)
        let has_list_v1_params =
            query.contains("prefix=") || query.contains("marker=") || query.contains("max-keys=");

        let response = match (
            &method,
            is_list_v2_operation,
            is_bucket_operation,
            key.as_str(),
            query.as_str(),
        ) {
            // Any GET with list-type=2 is a ListBucketV2 request
            (&Method::GET, true, _, _, query) => {
                debug!("Handling ListBucketV2 request (list-type=2 query)");
                self.handle_list_bucket(query, bucket_for_operation, &path)
                    .await
            }
            // GET / - ListBuckets
            (&Method::GET, false, false, "", _) if path == "/" => {
                debug!("Handling ListBuckets request");
                self.handle_list_buckets(&bucket_name).await
            }
            // GET /bucket?location - GetBucketLocation
            (&Method::GET, false, true, _, query) if query.contains("location") => {
                debug!(bucket = %bucket_for_operation, "Handling GetBucketLocation request");
                self.handle_get_bucket_location(bucket_for_operation).await
            }
            // GET /bucket with V1 list parameters - ListBucketV1
            (&Method::GET, false, true, _, query) if has_list_v1_params && !query.is_empty() => {
                debug!("Handling ListBucketV1 request (legacy API with query params)");
                self.handle_list_bucket_v1(query, bucket_for_operation, &path)
                    .await
            }
            // Path-style bucket root without query: GET /bucket/ or GET /bucket - default to V2
            (&Method::GET, false, true, _, _) => {
                debug!("Handling ListBucket request (path-style, no query - default to V2)");
                // Treat as ListBucket V2 with default parameters
                self.handle_list_bucket("list-type=2", bucket_for_operation, &path)
                    .await
            }
            // HEAD /bucket - HeadBucket
            (&Method::HEAD, false, true, "", _) => {
                debug!(bucket = %bucket_for_operation, "Handling HeadBucket request");
                self.handle_head_bucket(bucket_for_operation).await
            }
            // HEAD /key or HEAD /bucket/key - HeadObject
            (&Method::HEAD, false, false, key, _) if !key.is_empty() => {
                debug!(key = %key, "Handling HeadObject request");
                self.handle_head_object(key).await
            }
            // GET /key or GET /bucket/key - GetObject
            (&Method::GET, false, false, key, _) if !key.is_empty() => {
                debug!(key = %key, "Handling GetObject request");
                self.handle_get_object(key).await
            }
            // PUT /bucket - CreateBucket
            (&Method::PUT, false, true, "", _) if copy_source.is_none() => {
                debug!(bucket = %bucket_for_operation, "Handling CreateBucket request");
                self.handle_create_bucket(bucket_for_operation).await
            }
            // PUT /key with x-amz-copy-source header - CopyObject
            (&Method::PUT, false, false, key, _) if !key.is_empty() && copy_source.is_some() => {
                debug!(key = %key, copy_source = ?copy_source, "Handling CopyObject request");

                self.handle_copy_object(&copy_source.unwrap_or_default(), key)
                    .await
            }
            // PUT /key or PUT /bucket/key - PutObject
            (&Method::PUT, false, false, key, _) if !key.is_empty() => {
                debug!(key = %key, "Handling PutObject request");
                self.handle_put_object(buffered_body, key).await
            }
            // DELETE /bucket - DeleteBucket
            (&Method::DELETE, false, true, "", _) => {
                debug!(bucket = %bucket_for_operation, "Handling DeleteBucket request");
                self.handle_delete_bucket(bucket_for_operation).await
            }
            // DELETE /key or DELETE /bucket/key - DeleteObject
            (&Method::DELETE, false, false, key, _) if !key.is_empty() => {
                debug!(key = %key, "Handling DeleteObject request");
                self.handle_delete_object(key).await
            }
            // POST /?delete - DeleteObjects (batch delete)
            (&Method::POST, false, _, _, query) if query.contains("delete") => {
                debug!("Handling DeleteObjects request (batch delete)");
                self.handle_delete_objects(buffered_body, bucket_for_operation)
                    .await
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

    async fn handle_list_bucket_v1(
        &self,
        query: &str,
        bucket_name: &str,
        path: &str,
    ) -> Response<Full<Bytes>> {
        let mut max_keys = 1000;
        let mut marker = String::new();

        // Parse query parameters (V1 uses marker instead of continuation-token)
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
                    "marker" => marker = value.to_string(),
                    _ => {}
                }
            }
        }

        // Extract bucket name from path if present (same logic as V2)
        let path_trimmed = path.trim_start_matches('/');
        let bucket_from_path = if !path_trimmed.is_empty() && path_trimmed != "/" {
            if let Some(slash_pos) = path_trimmed.find('/') {
                Some(&path_trimmed[..slash_pos])
            } else {
                Some(path_trimmed)
            }
        } else {
            None
        };

        // Determine the prefix based on path and query
        let prefix = if let Some(bucket) = bucket_from_path {
            if let Some(query_prefix) = query_prefix {
                format!("{}/{}", bucket, query_prefix)
            } else if let Some(slash_pos) = path_trimmed.find('/') {
                let key_part = &path_trimmed[slash_pos + 1..];
                if !key_part.is_empty() {
                    path_trimmed.to_string()
                } else {
                    format!("{}/", bucket)
                }
            } else {
                format!("{}/", bucket)
            }
        } else if let Some(qp) = query_prefix {
            format!("{}/{}", bucket_name, qp)
        } else {
            format!("{}/", bucket_name)
        };

        let prefix_str = prefix.as_str();
        debug!(
            prefix = %prefix_str,
            max_keys = max_keys,
            marker = %marker,
            "Listing objects (V1)"
        );

        // List files with pagination (use marker as continuation token for V1)
        let marker_opt = if marker.is_empty() {
            None
        } else {
            Some(marker.as_str())
        };

        match self
            .filesystem
            .list_directory(Some(prefix_str), max_keys, marker_opt)
        {
            Ok((entries, next_marker)) => {
                debug!(count = entries.len(), "Listed objects (V1)");

                let response = ListBucketV1Response::new(
                    bucket_name.to_string(),
                    prefix_str.to_string(),
                    marker,
                    max_keys,
                    entries,
                    next_marker,
                );

                match response.to_xml() {
                    Ok(xml) => Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/xml")
                        .header("Content-Length", xml.len())
                        .body(Full::new(Bytes::from(xml)))
                        .unwrap(),
                    Err(e) => {
                        error!(error = %e, "Failed to serialize ListBucketV1 response");
                        self.internal_error_response()
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to list files");
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
        buffered_body: BufferedBody,
        key: &str,
    ) -> Response<Full<Bytes>> {
        // Get the body data from buffered body
        let body_vec = match buffered_body.to_vec().await {
            Ok(vec) => vec,
            Err(e) => {
                error!(key = %key, error = %e, "Failed to read buffered body");
                return self.internal_error_response();
            }
        };

        let body = Bytes::from(body_vec);

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

    async fn handle_create_bucket(&self, bucket: &str) -> Response<Full<Bytes>> {
        debug!(bucket = %bucket, "Handling CreateBucket request");

        match self.filesystem.create_bucket(bucket).await {
            Ok(()) => {
                debug!(bucket = %bucket, "CreateBucket success");
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Location", format!("/{}", bucket))
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    warn!(bucket = %bucket, "Bucket already exists");
                    self.bucket_already_exists_response(bucket)
                } else if e.kind() == std::io::ErrorKind::InvalidInput {
                    warn!(bucket = %bucket, error = %e, "Invalid bucket name");
                    self.invalid_bucket_name_response(&e.to_string())
                } else {
                    error!(bucket = %bucket, error = %e, "Failed to create bucket");
                    self.internal_error_response()
                }
            }
        }
    }

    async fn handle_delete_bucket(&self, bucket: &str) -> Response<Full<Bytes>> {
        debug!(bucket = %bucket, "Handling DeleteBucket request");

        match self.filesystem.delete_bucket(bucket).await {
            Ok(()) => {
                debug!(bucket = %bucket, "DeleteBucket success");
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    warn!(bucket = %bucket, "Bucket does not exist");
                    self.no_such_bucket_response(bucket)
                } else if e.kind() == std::io::ErrorKind::Other
                    && e.to_string().contains("not empty")
                {
                    warn!(bucket = %bucket, "Bucket is not empty");
                    self.bucket_not_empty_response(bucket)
                } else {
                    error!(bucket = %bucket, error = %e, "Failed to delete bucket");
                    self.internal_error_response()
                }
            }
        }
    }

    async fn handle_delete_object(&self, key: &str) -> Response<Full<Bytes>> {
        debug!(key = %key, "Handling DeleteObject request");

        match self.filesystem.delete_file(key).await {
            Ok(()) => {
                debug!(key = %key, "DeleteObject success");
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }
            Err(e) => {
                error!(key = %key, error = %e, "Failed to delete file");
                self.internal_error_response()
            }
        }
    }

    async fn handle_delete_objects(
        &self,
        body: BufferedBody,
        bucket: &str,
    ) -> Response<Full<Bytes>> {
        debug!(bucket = %bucket, "Handling DeleteObjects request (batch delete)");

        // Parse XML request body
        let body_bytes = match body.to_vec().await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!(error = %e, "Failed to read request body");
                return self.internal_error_response();
            }
        };

        let delete_request: DeleteRequest = match quick_xml::de::from_reader(body_bytes.as_ref()) {
            Ok(req) => req,
            Err(e) => {
                error!(error = %e, "Failed to parse DeleteObjects XML request");
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("Invalid XML request")))
                    .unwrap();
            }
        };

        let mut deleted = Vec::new();
        let mut errors = Vec::new();

        // Delete each object (prepend bucket name to key)
        for obj in delete_request.objects {
            let full_key = format!("{}/{}", bucket, obj.key);
            match self.filesystem.delete_file(&full_key).await {
                Ok(()) => {
                    debug!(key = %obj.key, full_key = %full_key, "Object deleted successfully");
                    if !delete_request.quiet {
                        deleted.push(DeletedObject { key: obj.key });
                    }
                }
                Err(e) => {
                    warn!(key = %obj.key, error = %e, "Failed to delete object");
                    errors.push(DeleteError {
                        key: obj.key,
                        code: "InternalError".to_string(),
                        message: e.to_string(),
                    });
                }
            }
        }

        // Build response
        let response = DeleteResponse { deleted, errors };

        match response.to_xml() {
            Ok(xml) => {
                debug!("DeleteObjects completed successfully");
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/xml")
                    .body(Full::new(Bytes::from(xml)))
                    .unwrap()
            }
            Err(e) => {
                error!(error = %e, "Failed to serialize DeleteObjects response");
                self.internal_error_response()
            }
        }
    }

    async fn handle_copy_object(&self, copy_source: &str, dest_key: &str) -> Response<Full<Bytes>> {
        debug!(copy_source = %copy_source, dest_key = %dest_key, "Handling CopyObject request");

        // Parse copy source - format is /bucket/key or bucket/key
        let source_key = copy_source.trim_start_matches('/');

        match self.filesystem.copy_file(source_key, dest_key).await {
            Ok(metadata) => {
                debug!(source = %source_key, dest = %dest_key, "CopyObject success");

                // Build response
                let response = CopyObjectResponse {
                    last_modified: metadata
                        .last_modified
                        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                        .to_string(),
                    etag: metadata.etag,
                };

                match response.to_xml() {
                    Ok(xml) => Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/xml")
                        .body(Full::new(Bytes::from(xml)))
                        .unwrap(),
                    Err(e) => {
                        error!(error = %e, "Failed to serialize CopyObject response");
                        self.internal_error_response()
                    }
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    warn!(source = %source_key, "Source object not found");
                    self.not_found_response()
                } else {
                    error!(source = %source_key, dest = %dest_key, error = %e, "Failed to copy object");
                    self.internal_error_response()
                }
            }
        }
    }

    async fn handle_get_bucket_location(&self, bucket: &str) -> Response<Full<Bytes>> {
        debug!(bucket = %bucket, "Handling GetBucketLocation request");

        // Check if bucket exists
        if !self.filesystem.bucket_exists(bucket) {
            warn!(bucket = %bucket, "Bucket does not exist");
            return self.no_such_bucket_response(bucket);
        }

        // Return the configured region
        let response = GetBucketLocationResponse {
            location: self.region.clone(),
        };

        match response.to_xml() {
            Ok(xml) => {
                debug!(bucket = %bucket, region = %self.region, "GetBucketLocation success");
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/xml")
                    .body(Full::new(Bytes::from(xml)))
                    .unwrap()
            }
            Err(e) => {
                error!(error = %e, "Failed to serialize GetBucketLocation response");
                self.internal_error_response()
            }
        }
    }

    async fn handle_head_bucket(&self, bucket: &str) -> Response<Full<Bytes>> {
        debug!(bucket = %bucket, "Handling HeadBucket request");

        if self.filesystem.bucket_exists(bucket) {
            debug!(bucket = %bucket, "HeadBucket success - bucket exists");
            Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::new()))
                .unwrap()
        } else {
            warn!(bucket = %bucket, "Bucket does not exist");
            self.no_such_bucket_response(bucket)
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

    fn access_denied_response(&self) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("Content-Type", "application/xml")
            .body(Full::new(Bytes::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
            )))
            .unwrap()
    }

    fn unauthorized_response(&self, reason: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("Content-Type", "application/xml")
            .header("WWW-Authenticate", "AWS4-HMAC-SHA256")
            .body(Full::new(Bytes::from(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>InvalidAccessKeyId</Code><Message>{}</Message></Error>",
                reason
            ))))
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

    fn bucket_already_exists_response(&self, bucket: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::CONFLICT)
            .header("Content-Type", "application/xml")
            .body(Full::new(Bytes::from(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>BucketAlreadyExists</Code><Message>The requested bucket name '{}' is not available.</Message></Error>",
                bucket
            ))))
            .unwrap()
    }

    fn bucket_not_empty_response(&self, bucket: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::CONFLICT)
            .header("Content-Type", "application/xml")
            .body(Full::new(Bytes::from(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>BucketNotEmpty</Code><Message>The bucket '{}' you tried to delete is not empty.</Message></Error>",
                bucket
            ))))
            .unwrap()
    }

    fn no_such_bucket_response(&self, bucket: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/xml")
            .body(Full::new(Bytes::from(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>NoSuchBucket</Code><Message>The specified bucket '{}' does not exist.</Message></Error>",
                bucket
            ))))
            .unwrap()
    }

    fn invalid_bucket_name_response(&self, reason: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/xml")
            .body(Full::new(Bytes::from(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>InvalidBucketName</Code><Message>{}</Message></Error>",
                reason
            ))))
            .unwrap()
    }
}
