//! S3 API request handlers and routing.
//!
//! Implements AWS S3-compatible API operations including bucket and object management,
//! with signature verification and IAM authorization.

use std::convert::Infallible;
use std::sync::Arc;

use http::header::{
    ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, HOST, LAST_MODIFIED, LOCATION,
    WWW_AUTHENTICATE,
};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Method, Request, Response, StatusCode};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::auth::{
    AuthContext, extract_bucket_and_key, http_method_to_s3_action, verify_sigv4,
    verify_streaming_sigv4,
};
use crate::body_buffer::BufferedBody;
use crate::credentials::CredentialStore;
use crate::db::DBService;
use crate::filesystem::FilesystemService;
use crate::multipart::MultipartManager;
use crate::policy::PolicyStore;
use crate::xml_responses::{
    CompleteMultipartUploadRequest, CompleteMultipartUploadResponse, CopyObjectResponse,
    CopyPartResponse, DeleteError, DeleteRequest, DeleteResponse, DeletedObject,
    GetBucketLocationResponse, GetObjectAttributesResponse, GetObjectTaggingResponse,
    InitiateMultipartUploadResponse, ListBucketResponse, ListBucketV1Response, ListBucketsResponse,
    ListMultipartUploadsResponse, ListPartsResponse, MultipartUploadItem, PartItem, Tag, TagSet,
    TaggingRequest,
};

pub struct S3Handler {
    server_addr: String,
    filesystem: Arc<RwLock<FilesystemService>>,
    policy_store: Arc<PolicyStore>,
    credentials_store: Arc<RwLock<CredentialStore>>,
    multipart_manager: Arc<RwLock<MultipartManager>>,
    db_service: Arc<DBService>,
    region: String,
}

impl S3Handler {
    pub fn new(
        filesystem: Arc<RwLock<FilesystemService>>,
        policy_store: Arc<PolicyStore>,
        credentials_store: Arc<RwLock<CredentialStore>>,
        multipart_manager: Arc<RwLock<MultipartManager>>,
        db_service: Arc<DBService>,
        region: String,
        server_addr: String,
    ) -> Self {
        Self {
            filesystem,
            policy_store,
            credentials_store,
            multipart_manager,
            db_service,
            region,
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

        // Check if this is a streaming/chunked request that needs decoding
        let needs_aws_chunk_decode =
            if let Some(content_sha256) = parts.headers.get("x-amz-content-sha256") {
                if let Ok(sha_str) = content_sha256.to_str() {
                    sha_str == "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
                } else {
                    false
                }
            } else {
                false
            };

        // Buffer the body (memory or disk depending on size)
        // Decode AWS chunks if this is a streaming upload
        let mut buffered_body =
            match BufferedBody::from_incoming(body, needs_aws_chunk_decode).await {
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

        // Check if this is a streaming/chunked request
        let is_streaming = if let Some(content_sha256) = parts.headers.get("x-amz-content-sha256") {
            if let Ok(sha_str) = content_sha256.to_str() {
                sha_str.starts_with("STREAMING-") || sha_str == "UNSIGNED-PAYLOAD"
            } else {
                false
            }
        } else {
            false
        };

        // Verify signature using appropriate method
        let verified = if is_streaming {
            debug!("Using streaming signature verification");
            match verify_streaming_sigv4(
                parts.clone(),
                self.credentials_store.clone(),
                &self.region,
            )
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "Streaming signature verification failed");
                    return Err(self
                        .unauthorized_response(&format!("Signature verification failed: {}", e)));
                }
            }
        } else {
            debug!("Using standard signature verification");
            // Reconstruct the request with the buffered body for verification
            // Normalize URI to path+query only (HTTP/2 sends absolute URIs but AWS SDK signs with relative)
            let mut normalized_parts = parts.clone();
            if let Some(path_and_query) = normalized_parts.uri.path_and_query() {
                normalized_parts.uri = path_and_query
                    .as_str()
                    .parse()
                    .unwrap_or_else(|_| parts.uri.clone());
            }

            // Add host header if missing (HTTP/2 uses :authority pseudo-header instead)
            if !normalized_parts.headers.contains_key(HOST)
                && let Some(authority) = parts.uri.authority()
            {
                normalized_parts.headers.insert(
                    HOST,
                    authority.as_str().parse().map_err(|_| {
                        error!("Failed to parse host header");
                        self.internal_error_response()
                    })?,
                );
            }

            let http_request = http::Request::from_parts(normalized_parts, body_vec.clone());

            match verify_sigv4(
                http_request,
                self.credentials_store.clone(),
                self.db_service.clone(),
                &self.region,
            )
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "Signature verification failed");
                    return Err(self
                        .unauthorized_response(&format!("Signature verification failed: {}", e)));
                }
            }
        };

        info!(
            access_key = %verified.access_key_id,
            "Request signature verified successfully"
        );

        Ok((Some(verified.access_key_id), buffered_body, parts))
    }

    pub async fn handle_request(
        &self,
        req: Request<hyper::body::Incoming>,
        remote_addr: std::net::SocketAddr,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        debug!(
            method = %req.method(),
            uri = %req.uri(),
            remote_addr = %remote_addr,
            has_range_header = req.headers().contains_key("range"),
            "Incoming S3 request"
        );

        // Verify signature and buffer body (or return error response)
        let (authenticated_username, mut buffered_body, parts) =
            match self.verify_and_buffer_request(req).await {
                Ok(result) => result,
                Err(response) => return Ok(response),
            };

        // Extract request metadata from parts
        let method = parts.method.clone();
        let path = parts.uri.path().to_string();
        let query = parts.uri.query().unwrap_or("").to_string();
        let mut bucket_name: String = String::new();

        if let Some(host_header) = parts.headers.get(HOST) {
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
            .and_then(|v| v.to_str().ok());

        // Check for x-amz-copy-source-range header for partial copies
        let copy_source_range = parts
            .headers
            .get("x-amz-copy-source-range")
            .and_then(|v| v.to_str().ok());

        info!(
            method = %method,
            path = %path,
            query = %query,
            bucket = %bucket_name,
            authenticated_user = ?authenticated_username.as_ref().unwrap_or(&"-".to_string()),
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
        let s3_action = http_method_to_s3_action(&method, &path, &query, is_bucket_operation);
        let (bucket, extracted_key) = extract_bucket_and_key(&path);

        // Use extracted bucket from path for path-style requests, fall back to host header
        let bucket_for_operation = match bucket.as_ref() {
            Some(val) => val.as_str(),
            None => {
                debug!(path=%path, "No bucket in path, using bucket from Host header if available");
                bucket_name.as_str()
            }
        };

        // Check if bucket name is reserved (admin UI paths)
        const RESERVED_BUCKET_NAMES: &[&str] = &[
            "admin",
            "api",
            "login",
            "logout",
            "oauth2",
            ".well-known",
            "config",
            "oidc",
            "crabcakes",
            "docs",
            "help",
            "lost+found",
        ];

        if !bucket_for_operation.is_empty() && RESERVED_BUCKET_NAMES.contains(&bucket_for_operation)
        {
            warn!(bucket = %bucket_for_operation, "Request to reserved bucket name");
            return Ok(self.invalid_bucket_name_response(&format!(
                "Bucket name '{}' is reserved and cannot be used",
                bucket_for_operation
            )));
        }

        // Check if this is a temporary credential (OAuth-based) - they get full access
        let is_temp_credential = if let Some(ref username) = authenticated_username {
            self.db_service
                .get_temporary_credentials(username)
                .await
                .ok()
                .flatten()
                .is_some()
        } else {
            false
        };

        // Build IAM request and evaluate policy (skip for temporary credentials)
        if is_temp_credential {
            debug!(access_key = ?authenticated_username, "Temporary credential - granting full access");
        } else {
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
        }

        // Parse multipart upload query parameters
        let is_multipart_create = query.contains("uploads") && !query.contains("uploadId");
        let upload_id_opt = if query.contains("uploadId=") {
            query
                .split('&')
                .find(|p| p.starts_with("uploadId="))
                .and_then(|p| p.strip_prefix("uploadId="))
                .map(|s| s.to_string())
        } else {
            None
        };
        let part_number_opt = if query.contains("partNumber=") {
            query
                .split('&')
                .find(|p| p.starts_with("partNumber="))
                .and_then(|p| p.strip_prefix("partNumber="))
                .and_then(|s| s.parse::<u32>().ok())
        } else {
            None
        };

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
            // Multipart upload operations
            // POST /key?uploads - CreateMultipartUpload
            (&Method::POST, false, false, key, _) if is_multipart_create && !key.is_empty() => {
                debug!(key = %key, "Handling CreateMultipartUpload request");
                self.handle_create_multipart_upload(bucket_for_operation, key)
                    .await
            }
            // PUT /key?uploadId=X&partNumber=Y with x-amz-copy-source - UploadPartCopy
            (&Method::PUT, false, false, key, _)
                if !key.is_empty()
                    && upload_id_opt.is_some()
                    && part_number_opt.is_some()
                    && copy_source.is_some() =>
            {
                let upload_id = upload_id_opt.as_deref().unwrap_or("");
                let part_number = part_number_opt.unwrap_or(0);
                let source = copy_source.unwrap_or("");
                debug!(
                    key = %key,
                    upload_id = %upload_id,
                    part_number = %part_number,
                    copy_source = %source,
                    "Handling UploadPartCopy request"
                );
                self.handle_upload_part_copy(
                    bucket_for_operation,
                    key,
                    upload_id,
                    part_number,
                    source,
                    copy_source_range,
                    &auth_context,
                )
                .await
            }
            // PUT /key?uploadId=X&partNumber=Y - UploadPart
            (&Method::PUT, false, false, key, _)
                if !key.is_empty() && upload_id_opt.is_some() && part_number_opt.is_some() =>
            {
                let upload_id = upload_id_opt.as_deref().unwrap_or("");
                let part_number = part_number_opt.unwrap_or(0);
                debug!(
                    key = %key,
                    upload_id = %upload_id,
                    part_number = %part_number,
                    "Handling UploadPart request"
                );
                self.handle_upload_part(
                    bucket_for_operation,
                    key,
                    upload_id,
                    part_number,
                    &mut buffered_body,
                )
                .await
            }
            // DELETE /key?uploadId=X - AbortMultipartUpload
            (&Method::DELETE, false, false, _, _) if upload_id_opt.is_some() => {
                let upload_id = upload_id_opt.as_deref().unwrap_or("");
                debug!(upload_id = %upload_id, "Handling AbortMultipartUpload request");
                self.handle_abort_multipart_upload(bucket_for_operation, upload_id)
                    .await
            }
            // GET /bucket?uploads - ListMultipartUploads
            (&Method::GET, false, true, _, query) if query.contains("uploads") => {
                debug!(bucket = %bucket_for_operation, "Handling ListMultipartUploads request");
                self.handle_list_multipart_uploads(bucket_for_operation)
                    .await
            }
            // GET /key?uploadId=X - ListParts
            (&Method::GET, false, false, key, _) if !key.is_empty() && upload_id_opt.is_some() => {
                let upload_id = upload_id_opt.as_deref().unwrap_or("");
                debug!(key = %key, upload_id = %upload_id, "Handling ListParts request");
                self.handle_list_parts(bucket_for_operation, key, upload_id)
                    .await
            }
            // POST /key?uploadId=X - CompleteMultipartUpload
            (&Method::POST, false, false, key, _) if !key.is_empty() && upload_id_opt.is_some() => {
                let upload_id = upload_id_opt.as_deref().unwrap_or("");
                debug!(key = %key, upload_id = %upload_id, "Handling CompleteMultipartUpload request");
                self.handle_complete_multipart_upload(
                    bucket_for_operation,
                    key,
                    upload_id,
                    &mut buffered_body,
                )
                .await
            }
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
            // GET /key?tagging - GetObjectTagging
            (&Method::GET, false, false, key, query)
                if !key.is_empty() && query.contains("tagging") =>
            {
                debug!(key = %key, "Handling GetObjectTagging request");
                self.handle_get_object_tagging(bucket_for_operation, key)
                    .await
            }
            // PUT /key?tagging - PutObjectTagging
            (&Method::PUT, false, false, key, query)
                if !key.is_empty() && query.contains("tagging") =>
            {
                debug!(key = %key, "Handling PutObjectTagging request");
                match buffered_body.to_vec().await {
                    Ok(body_bytes) => {
                        self.handle_put_object_tagging(bucket_for_operation, key, &body_bytes)
                            .await
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to read request body");
                        self.internal_error_response()
                    }
                }
            }
            // DELETE /key?tagging - DeleteObjectTagging
            (&Method::DELETE, false, false, key, query)
                if !key.is_empty() && query.contains("tagging") =>
            {
                debug!(key = %key, "Handling DeleteObjectTagging request");
                self.handle_delete_object_tagging(bucket_for_operation, key)
                    .await
            }
            // GET /key?attributes - GetObjectAttributes
            (&Method::GET, false, false, key, query)
                if !key.is_empty() && query.contains("attributes") =>
            {
                debug!(key = %key, "Handling GetObjectAttributes request");
                self.handle_get_object_attributes(bucket_for_operation, key)
                    .await
            }
            // GET /key or GET /bucket/key - GetObject
            (&Method::GET, false, false, key, _) if !key.is_empty() => {
                debug!(key = %key, "Handling GetObject request");
                self.handle_get_object(key, &parts).await
            }
            // PUT /bucket - CreateBucket
            (&Method::PUT, false, true, "", _) if copy_source.is_none() => {
                debug!(bucket = %bucket_for_operation, "Handling CreateBucket request");
                self.handle_create_bucket(bucket_for_operation).await
            }
            // PUT /key with x-amz-copy-source header - CopyObject
            (&Method::PUT, false, false, key, _) if !key.is_empty() && copy_source.is_some() => {
                debug!(key = %key, copy_source = ?copy_source, "Handling CopyObject request");
                match copy_source {
                    None => {
                        Response::builder().status(StatusCode::BAD_REQUEST).body( Full::new(Bytes::from_static(
                            b"<Error><Code>InvalidArgument</Code><Message>Missing x-amz-copy-source header</Message></Error>",
                        ))).unwrap_or(self.internal_error_response())
                    }
                    Some(copy_source) => self.handle_copy_object(copy_source, key, &auth_context).await,
                }
            }
            // PUT /key or PUT /bucket/key - PutObject
            (&Method::PUT, false, false, key, _) if !key.is_empty() => {
                debug!(key = %key, "Handling PutObject request");
                self.handle_put_object(&mut buffered_body, key).await
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
                self.handle_delete_objects(&mut buffered_body, bucket_for_operation)
                    .await
            }
            _ => {
                warn!(method = %method, path = %path, "Unknown request pattern");
                self.not_found_response()
            }
        };

        let status = response.status();

        // Log request with all relevant details
        let user_str = authenticated_username.as_deref().unwrap_or("-");
        if key.is_empty() {
            info!(
                client_ip = %remote_addr.ip(),
                method = %method,
                path = %path,
                bucket = %bucket_for_operation,
                status = %status.as_u16(),
                user = %user_str,
                "Request completed"
            );
        } else {
            info!(
                client_ip = %remote_addr.ip(),
                method = %method,
                path = %path,
                bucket = %bucket_for_operation,
                key = %key,
                status = %status.as_u16(),
                user = %user_str,
                "Request completed"
            );
        }

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

        match self.filesystem.read().await.list_directory(
            prefix.as_deref(),
            max_keys,
            continuation_token,
        ) {
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
                    Ok(xml) =>
                    {
                        #[allow(clippy::expect_used)]
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/xml")
                            .header(CONTENT_LENGTH, xml.len())
                            .body(Full::new(Bytes::from(xml)))
                            .expect("Failed to generate a ListBucketV1 response")
                    }
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
            .read()
            .await
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
                    Ok(xml) =>
                    {
                        #[allow(clippy::expect_used)]
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/xml")
                            .header(CONTENT_LENGTH, xml.len())
                            .body(Full::new(Bytes::from(xml)))
                            .expect("Failed to generate a ListBucketV1 response")
                    }
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
        match self.filesystem.read().await.list_buckets() {
            Ok(buckets) => {
                debug!(count = buckets.len(), "Listed buckets");
                let response = ListBucketsResponse::from_buckets(buckets);

                match response.to_xml() {
                    Ok(xml) =>
                    {
                        #[allow(clippy::expect_used)]
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/xml")
                            .header(CONTENT_LENGTH, xml.len())
                            .body(Full::new(Bytes::from(xml)))
                            .expect("Failed to generate a ListBuckets response")
                    }
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
        match self.filesystem.read().await.get_file_metadata(key) {
            Ok(metadata) => {
                debug!(key = %key, size = metadata.size, "HeadObject success");

                #[allow(clippy::expect_used)]
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, metadata.content_type)
                    .header(CONTENT_LENGTH, metadata.size)
                    .header(
                        LAST_MODIFIED,
                        metadata
                            .last_modified
                            .format("%a, %d %b %Y %H:%M:%S GMT")
                            .to_string(),
                    )
                    .header("ETag", metadata.etag)
                    .body(Full::new(Bytes::new()))
                    .expect("Failed to generate a HeadObject response")
            }
            Err(e) => {
                warn!(key = %key, error = %e, "HeadObject failed: file not found");
                self.not_found_response()
            }
        }
    }

    async fn handle_get_object(
        &self,
        key: &str,
        parts: &http::request::Parts,
    ) -> Response<Full<Bytes>> {
        let range_header = parts.headers.get("range").and_then(|h| h.to_str().ok());
        self.handle_get_object_with_range(key, range_header).await
    }

    async fn handle_get_object_with_range(
        &self,
        key: &str,
        range_header: Option<&str>,
    ) -> Response<Full<Bytes>> {
        match self.filesystem.read().await.get_file_metadata(key) {
            Ok(metadata) => {
                // Parse range header if present
                let (start, end, is_range_request) = if let Some(range_str) = range_header {
                    // Range header format: "bytes=start-end"
                    if let Some(bytes_range) = range_str.strip_prefix("bytes=") {
                        let parts: Vec<&str> = bytes_range.split('-').collect();
                        if parts.len() == 2 {
                            let start = parts[0].parse::<u64>().unwrap_or(0);
                            let end = if parts[1].is_empty() {
                                metadata.size - 1
                            } else {
                                parts[1]
                                    .parse::<u64>()
                                    .unwrap_or(metadata.size - 1)
                                    .min(metadata.size - 1)
                            };
                            (start, end, true)
                        } else {
                            (0, metadata.size - 1, false)
                        }
                    } else {
                        (0, metadata.size - 1, false)
                    }
                } else {
                    (0, metadata.size - 1, false)
                };

                match File::open(&metadata.path).await {
                    Ok(mut file) => {
                        let contents = if is_range_request {
                            // Seek to start position
                            use tokio::io::AsyncSeekExt;
                            if let Err(e) = file.seek(std::io::SeekFrom::Start(start)).await {
                                error!(key = %key, error = %e, "Failed to seek to range start");
                                return self.internal_error_response();
                            }

                            // Read the requested range
                            let range_len = (end - start + 1) as usize;
                            let mut buffer = vec![0u8; range_len];
                            use tokio::io::AsyncReadExt;
                            match file.read_exact(&mut buffer).await {
                                Ok(_) => buffer,
                                Err(e) => {
                                    error!(key = %key, error = %e, "Failed to read range");
                                    return self.internal_error_response();
                                }
                            }
                        } else {
                            // Read entire file
                            let mut buffer = Vec::new();
                            use tokio::io::AsyncReadExt;
                            match file.read_to_end(&mut buffer).await {
                                Ok(_) => buffer,
                                Err(e) => {
                                    error!(key = %key, error = %e, "Failed to read file");
                                    return self.internal_error_response();
                                }
                            }
                        };

                        debug!(
                            key = %key,
                            is_range = is_range_request,
                            start = start,
                            end = end,
                            bytes_read = contents.len(),
                            metadata_size = metadata.size,
                            path = %metadata.path.display(),
                            "GetObject success"
                        );

                        let mut response = Response::builder()
                            .header(CONTENT_TYPE, metadata.content_type)
                            .header(
                                "Last-Modified",
                                metadata
                                    .last_modified
                                    .format("%a, %d %b %Y %H:%M:%S GMT")
                                    .to_string(),
                            )
                            .header("ETag", metadata.etag)
                            .header(ACCEPT_RANGES, "bytes");

                        if is_range_request {
                            response = response
                                .status(StatusCode::PARTIAL_CONTENT)
                                .header(CONTENT_LENGTH, contents.len())
                                .header(
                                    CONTENT_RANGE,
                                    format!("bytes {}-{}/{}", start, end, metadata.size),
                                );
                        } else {
                            response = response
                                .status(StatusCode::OK)
                                .header(CONTENT_LENGTH, metadata.size);
                        }

                        #[allow(clippy::expect_used)]
                        response
                            .body(Full::new(Bytes::from(contents)))
                            .expect("Failed to generate GetObject response")
                    }
                    Err(e) => {
                        error!(key = %key, error = %e, "Failed to open file");
                        self.internal_error_response()
                    }
                }
            }
            Err(e) => {
                warn!(key = %key, error = %e, "GetObject failed: file not found");
                self.not_found_response()
            }
        }
    }

    async fn handle_put_object(
        &self,
        buffered_body: &mut BufferedBody,
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
        match self.filesystem.write().await.write_file(key, &body).await {
            Ok(metadata) => {
                debug!(key = %key, size = metadata.size, "PutObject success");
                #[allow(clippy::expect_used)]
                Response::builder()
                    .status(StatusCode::OK)
                    .header("ETag", metadata.etag)
                    .body(Full::new(Bytes::new()))
                    .expect("Failed to generate a PutObject response")
            }
            Err(e) => {
                error!(key = %key, error = %e, "Failed to write file");
                self.internal_error_response()
            }
        }
    }

    async fn handle_create_bucket(&self, bucket: &str) -> Response<Full<Bytes>> {
        debug!(bucket = %bucket, "Handling CreateBucket request");

        match self.filesystem.write().await.create_bucket(bucket).await {
            Ok(()) => {
                debug!(bucket = %bucket, "CreateBucket success");
                #[allow(clippy::expect_used)]
                Response::builder()
                    .status(StatusCode::OK)
                    .header(LOCATION, format!("/{}", bucket))
                    .body(Full::new(Bytes::new()))
                    .expect("Failed to build CreateBucket response")
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

        match self.filesystem.write().await.delete_bucket(bucket).await {
            Ok(()) => {
                debug!(bucket = %bucket, "DeleteBucket success");
                #[allow(clippy::expect_used)]
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::new()))
                    .expect("Failed to generate a DeleteBucket response")
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

        match self.filesystem.write().await.delete_file(key).await {
            Ok(()) => {
                debug!(key = %key, "DeleteObject success");
                #[allow(clippy::expect_used)]
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::new()))
                    .expect("Failed to generate a DeleteObject response")
            }
            Err(e) => {
                error!(key = %key, error = %e, "Failed to delete file");
                self.internal_error_response()
            }
        }
    }

    async fn handle_delete_objects(
        &self,
        body: &mut BufferedBody,
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
                #[allow(clippy::expect_used)]
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("Invalid XML request")))
                    .expect("Failed to generate a DeleteObjects response");
            }
        };

        let mut deleted = Vec::new();
        let mut errors = Vec::new();

        // Delete each object (prepend bucket name to key)
        for obj in delete_request.objects {
            let full_key = format!("{}/{}", bucket, obj.key);
            match self.filesystem.write().await.delete_file(&full_key).await {
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

                #[allow(clippy::expect_used)]
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/xml")
                    .body(Full::new(Bytes::from(xml)))
                    .expect("Failed to generate a DeleteObjects response")
            }
            Err(e) => {
                error!(error = %e, "Failed to serialize DeleteObjects response");
                self.internal_error_response()
            }
        }
    }

    async fn handle_copy_object(
        &self,
        copy_source: &str,
        dest_key: &str,
        auth_context: &AuthContext,
    ) -> Response<Full<Bytes>> {
        debug!(copy_source = %copy_source, dest_key = %dest_key, "Handling CopyObject request");

        // Parse copy source - format is /bucket/key or bucket/key
        let source_key = copy_source.trim_start_matches('/');

        // Extract bucket and key from source for IAM check
        let (source_bucket, source_object_key) =
            extract_bucket_and_key(&format!("/{}", source_key));

        // Check s3:GetObject permission on source
        let source_iam_request = match auth_context.build_iam_request(
            "s3:GetObject",
            source_bucket.as_deref(),
            source_object_key.as_deref(),
        ) {
            Ok(req) => req,
            Err(e) => {
                error!(error = %e, "Failed to build IAM request for source");
                return self.internal_error_response();
            }
        };

        match self
            .policy_store
            .evaluate_request(&source_iam_request)
            .await
        {
            Ok(true) => {
                debug!("Authorization granted for source object");
            }
            Ok(false) => {
                warn!(
                    principal = ?source_iam_request.principal,
                    action = "s3:GetObject",
                    resource = ?source_iam_request.resource,
                    "Access denied for source object"
                );
                return self.access_denied_response();
            }
            Err(e) => {
                error!(error = %e, "Policy evaluation failed for source");
                return self.internal_error_response();
            }
        }

        match self
            .filesystem
            .write()
            .await
            .copy_file(source_key, dest_key)
            .await
        {
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
                    Ok(xml) =>
                    {
                        #[allow(clippy::expect_used)]
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/xml")
                            .body(Full::new(Bytes::from(xml)))
                            .expect("Failed to generate a CopyObject response")
                    }
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
        if !self.filesystem.read().await.bucket_exists(bucket) {
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
                #[allow(clippy::expect_used)]
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/xml")
                    .body(Full::new(Bytes::from(xml)))
                    .expect("Failed to generate a GetBucketLocation response")
            }
            Err(e) => {
                error!(error = %e, "Failed to serialize GetBucketLocation response");
                self.internal_error_response()
            }
        }
    }

    async fn handle_head_bucket(&self, bucket: &str) -> Response<Full<Bytes>> {
        debug!(bucket = %bucket, "Handling HeadBucket request");

        if self.filesystem.read().await.bucket_exists(bucket) {
            debug!(bucket = %bucket, "HeadBucket success - bucket exists");
            #[allow(clippy::expect_used)]
            Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::new()))
                .expect("Failed to generate a head bucket response")
        } else {
            warn!(bucket = %bucket, "Bucket does not exist");
            self.no_such_bucket_response(bucket)
        }
    }

    // Multipart upload handlers

    async fn handle_create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
    ) -> Response<Full<Bytes>> {
        debug!(bucket = %bucket, key = %key, "Handling CreateMultipartUpload request");

        // Verify bucket exists
        if !self.filesystem.read().await.bucket_exists(bucket) {
            warn!(bucket = %bucket, "Bucket does not exist");
            return self.no_such_bucket_response(bucket);
        }

        // Create multipart upload
        match self
            .multipart_manager
            .write()
            .await
            .create_upload(bucket, key)
            .await
        {
            Ok(metadata) => {
                debug!(
                    upload_id = %metadata.upload_id,
                    bucket = %bucket,
                    key = %key,
                    "CreateMultipartUpload success"
                );

                let response = InitiateMultipartUploadResponse {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    upload_id: metadata.upload_id,
                };

                match response.to_xml() {
                    Ok(xml) =>
                    {
                        #[allow(clippy::expect_used)]
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/xml")
                            .body(Full::new(Bytes::from(xml)))
                            .expect("Failed to generate CreateMultipartUpload response")
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to serialize CreateMultipartUpload response");
                        self.internal_error_response()
                    }
                }
            }
            Err(e) => {
                error!(
                    bucket = %bucket,
                    key = %key,
                    error = %e,
                    "Failed to create multipart upload"
                );
                self.internal_error_response()
            }
        }
    }

    async fn handle_upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: u32,
        body: &mut BufferedBody,
    ) -> Response<Full<Bytes>> {
        debug!(
            bucket = %bucket,
            key = %key,
            upload_id = %upload_id,
            part_number = %part_number,
            "Handling UploadPart request"
        );

        // Get body data
        let body_vec = match body.to_vec().await {
            Ok(vec) => vec,
            Err(e) => {
                error!(error = %e, "Failed to read request body");
                return self.internal_error_response();
            }
        };

        // Upload part
        match self
            .multipart_manager
            .write()
            .await
            .upload_part(bucket, upload_id, part_number, &body_vec)
            .await
        {
            Ok(part_info) => {
                debug!(
                    upload_id = %upload_id,
                    part_number = %part_number,
                    etag = %part_info.etag,
                    "UploadPart success"
                );

                #[allow(clippy::expect_used)]
                Response::builder()
                    .status(StatusCode::OK)
                    .header("ETag", part_info.etag)
                    .body(Full::new(Bytes::new()))
                    .expect("Failed to generate UploadPart response")
            }
            Err(e) => {
                error!(
                    upload_id = %upload_id,
                    part_number = %part_number,
                    error = %e,
                    "Failed to upload part"
                );
                self.internal_error_response()
            }
        }
    }

    async fn handle_upload_part_copy(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: u32,
        copy_source: &str,
        copy_source_range: Option<&str>,
        auth_context: &AuthContext,
    ) -> Response<Full<Bytes>> {
        debug!(
            bucket = %bucket,
            key = %key,
            upload_id = %upload_id,
            part_number = %part_number,
            copy_source = %copy_source,
            copy_source_range = ?copy_source_range,
            "Handling UploadPartCopy request"
        );

        // Parse copy source - format is /bucket/key or bucket/key
        let source_key = copy_source.trim_start_matches('/');

        // Extract bucket and key from source for IAM check
        let (source_bucket, source_object_key) =
            extract_bucket_and_key(&format!("/{}", source_key));

        // Check s3:GetObject permission on source
        let source_iam_request = match auth_context.build_iam_request(
            "s3:GetObject",
            source_bucket.as_deref(),
            source_object_key.as_deref(),
        ) {
            Ok(req) => req,
            Err(e) => {
                error!(error = %e, "Failed to build IAM request for source");
                return self.internal_error_response();
            }
        };

        match self
            .policy_store
            .evaluate_request(&source_iam_request)
            .await
        {
            Ok(true) => {
                debug!("Authorization granted for source object");
            }
            Ok(false) => {
                warn!(
                    principal = ?source_iam_request.principal,
                    action = "s3:GetObject",
                    resource = ?source_iam_request.resource,
                    "Access denied for source object"
                );
                return self.access_denied_response();
            }
            Err(e) => {
                error!(error = %e, "Policy evaluation failed for source");
                return self.internal_error_response();
            }
        }

        // Read source object
        let source_path = self.filesystem.read().await.resolve_path(source_key);
        let mut file = match File::open(&source_path).await {
            Ok(f) => f,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    warn!(source = %source_key, "Source object not found");
                    return self.not_found_response();
                }
                error!(source = %source_key, error = %e, "Failed to open source file");
                return self.internal_error_response();
            }
        };

        // Read data (with optional range)
        let data = if let Some(range_str) = copy_source_range {
            // Parse range: "bytes=start-end"
            if let Some(range_spec) = range_str.strip_prefix("bytes=") {
                if let Some((start_str, end_str)) = range_spec.split_once('-') {
                    let start: u64 = match start_str.parse() {
                        Ok(s) => s,
                        Err(_) => {
                            warn!(range = %range_str, "Invalid range format");
                            #[allow(clippy::expect_used)]
                            return Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Full::new(Bytes::from("Invalid range format")))
                                .expect("Failed to generate error response");
                        }
                    };
                    let end: u64 = match end_str.parse() {
                        Ok(e) => e,
                        Err(_) => {
                            warn!(range = %range_str, "Invalid range format");
                            #[allow(clippy::expect_used)]
                            return Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Full::new(Bytes::from("Invalid range format")))
                                .expect("Failed to generate error response");
                        }
                    };

                    // Seek to start position
                    if let Err(e) = file.seek(std::io::SeekFrom::Start(start)).await {
                        error!(error = %e, "Failed to seek in source file");
                        return self.internal_error_response();
                    }

                    // Read the range
                    let bytes_to_read = (end - start + 1) as usize;
                    let mut buffer = vec![0u8; bytes_to_read];
                    match file.read_exact(&mut buffer).await {
                        Ok(_) => buffer,
                        Err(e) => {
                            error!(error = %e, "Failed to read source file range");
                            return self.internal_error_response();
                        }
                    }
                } else {
                    warn!(range = %range_str, "Invalid range format - missing dash");
                    #[allow(clippy::expect_used)]
                    return Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::new(Bytes::from("Invalid range format")))
                        .expect("Failed to generate error response");
                }
            } else {
                warn!(range = %range_str, "Invalid range format - must start with bytes=");
                #[allow(clippy::expect_used)]
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("Invalid range format")))
                    .expect("Failed to generate error response");
            }
        } else {
            // Read entire file
            let mut contents = Vec::new();
            match file.read_to_end(&mut contents).await {
                Ok(_) => contents,
                Err(e) => {
                    error!(source = %source_key, error = %e, "Failed to read source file");
                    return self.internal_error_response();
                }
            }
        };

        // Upload the data as a part
        match self
            .multipart_manager
            .write()
            .await
            .upload_part(bucket, upload_id, part_number, &data)
            .await
        {
            Ok(part_info) => {
                debug!(
                    upload_id = %upload_id,
                    part_number = %part_number,
                    etag = %part_info.etag,
                    source = %source_key,
                    "UploadPartCopy success"
                );

                // Create CopyPartResult XML response
                let response = CopyPartResponse {
                    last_modified: part_info
                        .last_modified
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    etag: part_info.etag.clone(),
                };

                let xml_body = match response.to_xml() {
                    Ok(xml) => xml,
                    Err(e) => {
                        error!(error = %e, "Failed to serialize CopyPartResult XML");
                        return self.internal_error_response();
                    }
                };

                #[allow(clippy::expect_used)]
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/xml")
                    .header("ETag", part_info.etag)
                    .body(Full::new(Bytes::from(xml_body)))
                    .expect("Failed to generate UploadPartCopy response")
            }
            Err(e) => {
                error!(
                    upload_id = %upload_id,
                    part_number = %part_number,
                    error = %e,
                    "Failed to upload part copy"
                );
                self.internal_error_response()
            }
        }
    }

    async fn handle_abort_multipart_upload(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> Response<Full<Bytes>> {
        debug!(
            bucket = %bucket,
            upload_id = %upload_id,
            "Handling AbortMultipartUpload request"
        );

        match self
            .multipart_manager
            .write()
            .await
            .abort_upload(bucket, upload_id)
            .await
        {
            Ok(()) => {
                debug!(upload_id = %upload_id, "AbortMultipartUpload success");
                #[allow(clippy::expect_used)]
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::new()))
                    .expect("Failed to generate AbortMultipartUpload response")
            }
            Err(e) => {
                error!(upload_id = %upload_id, error = %e, "Failed to abort multipart upload");
                self.internal_error_response()
            }
        }
    }

    async fn handle_list_multipart_uploads(&self, bucket: &str) -> Response<Full<Bytes>> {
        debug!(bucket = %bucket, "Handling ListMultipartUploads request");

        // Verify bucket exists
        if !self.filesystem.read().await.bucket_exists(bucket) {
            warn!(bucket = %bucket, "Bucket does not exist");
            return self.no_such_bucket_response(bucket);
        }

        match self
            .multipart_manager
            .read()
            .await
            .list_uploads(bucket)
            .await
        {
            Ok(uploads) => {
                debug!(count = uploads.len(), "ListMultipartUploads success");

                let upload_items: Vec<MultipartUploadItem> = uploads
                    .into_iter()
                    .map(|metadata| MultipartUploadItem {
                        key: metadata.key,
                        upload_id: metadata.upload_id,
                        initiated: metadata
                            .initiated
                            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                            .to_string(),
                    })
                    .collect();

                let response = ListMultipartUploadsResponse {
                    bucket: bucket.to_string(),
                    uploads: upload_items,
                };

                match response.to_xml() {
                    Ok(xml) =>
                    {
                        #[allow(clippy::expect_used)]
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/xml")
                            .body(Full::new(Bytes::from(xml)))
                            .expect("Failed to generate ListMultipartUploads response")
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to serialize ListMultipartUploads response");
                        self.internal_error_response()
                    }
                }
            }
            Err(e) => {
                error!(bucket = %bucket, error = %e, "Failed to list multipart uploads");
                self.internal_error_response()
            }
        }
    }

    async fn handle_list_parts(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Response<Full<Bytes>> {
        debug!(
            bucket = %bucket,
            key = %key,
            upload_id = %upload_id,
            "Handling ListParts request"
        );

        match self
            .multipart_manager
            .read()
            .await
            .list_parts(bucket, upload_id)
            .await
        {
            Ok(parts) => {
                debug!(count = parts.len(), "ListParts success");

                let part_items: Vec<PartItem> = parts
                    .into_iter()
                    .map(|part| PartItem {
                        part_number: part.part_number,
                        etag: part.etag,
                        size: part.size,
                        last_modified: part
                            .last_modified
                            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                            .to_string(),
                    })
                    .collect();

                let response = ListPartsResponse {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    upload_id: upload_id.to_string(),
                    parts: part_items,
                };

                match response.to_xml() {
                    Ok(xml) =>
                    {
                        #[allow(clippy::expect_used)]
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/xml")
                            .body(Full::new(Bytes::from(xml)))
                            .expect("Failed to generate ListParts response")
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to serialize ListParts response");
                        self.internal_error_response()
                    }
                }
            }
            Err(e) => {
                error!(upload_id = %upload_id, error = %e, "Failed to list parts");
                self.internal_error_response()
            }
        }
    }

    async fn handle_complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        body: &mut BufferedBody,
    ) -> Response<Full<Bytes>> {
        debug!(
            bucket = %bucket,
            key = %key,
            upload_id = %upload_id,
            "Handling CompleteMultipartUpload request"
        );

        // Parse XML request body
        let body_bytes = match body.to_vec().await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!(error = %e, "Failed to read request body");
                return self.internal_error_response();
            }
        };

        let complete_request: CompleteMultipartUploadRequest =
            match quick_xml::de::from_reader(body_bytes.as_ref()) {
                Ok(req) => req,
                Err(e) => {
                    error!(error = %e, "Failed to parse CompleteMultipartUpload XML request");
                    #[allow(clippy::expect_used)]
                    return Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::new(Bytes::from("Invalid XML request")))
                        .expect("Failed to generate error response");
                }
            };

        // Extract parts as tuples (part_number, etag)
        let parts: Vec<(u32, String)> = complete_request
            .parts
            .into_iter()
            .map(|p| (p.part_number, p.etag))
            .collect();

        // Build full key path
        let dest_path = self.filesystem.read().await.resolve_path(key);

        // Complete multipart upload
        match self
            .multipart_manager
            .write()
            .await
            .complete_upload(bucket, upload_id, &parts, &dest_path)
            .await
        {
            Ok(etag) => {
                debug!(
                    upload_id = %upload_id,
                    bucket = %bucket,
                    key = %key,
                    "CompleteMultipartUpload success"
                );

                let response = CompleteMultipartUploadResponse {
                    location: format!("/{}/{}", bucket, key),
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    etag,
                };

                match response.to_xml() {
                    Ok(xml) =>
                    {
                        #[allow(clippy::expect_used)]
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/xml")
                            .body(Full::new(Bytes::from(xml)))
                            .expect("Failed to generate CompleteMultipartUpload response")
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to serialize CompleteMultipartUpload response");
                        self.internal_error_response()
                    }
                }
            }
            Err(e) => {
                error!(
                    upload_id = %upload_id,
                    error = %e,
                    "Failed to complete multipart upload"
                );
                self.internal_error_response()
            }
        }
    }

    // ===== Object Tagging Handlers =====

    async fn handle_put_object_tagging(
        &self,
        bucket: &str,
        key: &str,
        body: &[u8],
    ) -> Response<Full<Bytes>> {
        debug!(bucket = %bucket, key = %key, "Handling PutObjectTagging request");

        // Parse XML request
        let tagging_request: TaggingRequest = match quick_xml::de::from_reader(body) {
            Ok(req) => req,
            Err(e) => {
                error!(error = %e, "Failed to parse tagging request");
                return self.internal_error_response();
            }
        };

        // Convert tags to vec of tuples
        let tags: Vec<(String, String)> = tagging_request
            .tag_set
            .tags
            .into_iter()
            .map(|t| (t.key, t.value))
            .collect();

        // Store tags
        match self.db_service.put_tags(bucket, key, tags).await {
            Ok(()) => {
                debug!(bucket = %bucket, key = %key, "Tags stored successfully");
                #[allow(clippy::expect_used)]
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::new()))
                    .expect("Failed to generate PutObjectTagging response")
            }
            Err(e) => {
                error!(bucket = %bucket, key = %key, error = %e, "Failed to store tags");
                self.internal_error_response()
            }
        }
    }

    async fn handle_get_object_tagging(&self, bucket: &str, key: &str) -> Response<Full<Bytes>> {
        debug!(bucket = %bucket, key = %key, "Handling GetObjectTagging request");

        // Get tags from database
        match self.db_service.get_tags(bucket, key).await {
            Ok(tags) => {
                let tag_set = TagSet {
                    tags: tags
                        .into_iter()
                        .map(|(k, v)| Tag { key: k, value: v })
                        .collect(),
                };

                let response = GetObjectTaggingResponse { tag_set };

                match response.to_xml() {
                    Ok(xml) =>
                    {
                        #[allow(clippy::expect_used)]
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/xml")
                            .body(Full::new(Bytes::from(xml)))
                            .expect("Failed to generate GetObjectTagging response")
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to serialize tagging response");
                        self.internal_error_response()
                    }
                }
            }
            Err(e) => {
                error!(bucket = %bucket, key = %key, error = %e, "Failed to get tags");
                self.internal_error_response()
            }
        }
    }

    async fn handle_delete_object_tagging(&self, bucket: &str, key: &str) -> Response<Full<Bytes>> {
        debug!(bucket = %bucket, key = %key, "Handling DeleteObjectTagging request");

        match self.db_service.delete_tags(bucket, key).await {
            Ok(()) => {
                debug!(bucket = %bucket, key = %key, "Tags deleted successfully");
                #[allow(clippy::expect_used)]
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::new()))
                    .expect("Failed to generate DeleteObjectTagging response")
            }
            Err(e) => {
                error!(bucket = %bucket, key = %key, error = %e, "Failed to delete tags");
                self.internal_error_response()
            }
        }
    }

    async fn handle_get_object_attributes(&self, bucket: &str, key: &str) -> Response<Full<Bytes>> {
        debug!(bucket = %bucket, key = %key, "Handling GetObjectAttributes request");

        // Resolve the file path
        let file_key = if bucket.is_empty() {
            key
        } else {
            &format!("{}/{}", bucket, key)
        };
        let file_path = self.filesystem.read().await.resolve_path(file_key);

        // Get file metadata
        match tokio::fs::metadata(&file_path).await {
            Ok(metadata) => {
                let object_size = metadata.len();

                // Generate ETag (simplified - using file size and modification time)
                let modified_time = metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let etag = format!("\"{:x}\"", object_size ^ modified_time);

                let last_modified = chrono::DateTime::<chrono::Utc>::from(
                    metadata.modified().unwrap_or(std::time::SystemTime::now()),
                )
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

                let response = GetObjectAttributesResponse {
                    etag: Some(etag),
                    last_modified: Some(last_modified),
                    object_size: Some(object_size),
                };

                match response.to_xml() {
                    Ok(xml) =>
                    {
                        #[allow(clippy::expect_used)]
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/xml")
                            .body(Full::new(Bytes::from(xml)))
                            .expect("Failed to generate GetObjectAttributes response")
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to serialize attributes response");
                        self.internal_error_response()
                    }
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    self.not_found_response()
                } else {
                    error!(error = %e, "Failed to get file metadata");
                    self.internal_error_response()
                }
            }
        }
    }

    fn not_found_response(&self) -> Response<Full<Bytes>> {
        #[allow(clippy::expect_used)]
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(CONTENT_TYPE, "application/xml")
            .body(Full::new(Bytes::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>",
            )))
            .expect("Failed to generate a not found response")
    }

    fn access_denied_response(&self) -> Response<Full<Bytes>> {
        #[allow(clippy::expect_used)]
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(CONTENT_TYPE, "application/xml")
            .body(Full::new(Bytes::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
            )))
            .expect("Failed to generate an access denied response")
    }

    fn unauthorized_response(&self, reason: &str) -> Response<Full<Bytes>> {
        #[allow(clippy::expect_used)]
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(CONTENT_TYPE, "application/xml")
            .header(WWW_AUTHENTICATE, "AWS4-HMAC-SHA256")
            .body(Full::new(Bytes::from(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>InvalidAccessKeyId</Code><Message>{}</Message></Error>",
                reason
            ))))
            .expect("Failed to generate an unauthorized response")
    }

    fn internal_error_response(&self) -> Response<Full<Bytes>> {
        #[allow(clippy::expect_used)]
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(CONTENT_TYPE, "application/xml")
            .body(Full::new(Bytes::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>InternalError</Code><Message>We encountered an internal error. Please try again.</Message></Error>",
            )))
            .expect("Failed to generate an internal error response")
    }

    fn bucket_already_exists_response(&self, bucket: &str) -> Response<Full<Bytes>> {
        #[allow(clippy::expect_used)]
        Response::builder()
            .status(StatusCode::CONFLICT)
            .header(CONTENT_TYPE, "application/xml")
            .body(Full::new(Bytes::from(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>BucketAlreadyExists</Code><Message>The requested bucket name '{}' is not available.</Message></Error>",
                bucket
            ))))
            .expect("Failed to generate a bucket already exists response")
    }

    fn bucket_not_empty_response(&self, bucket: &str) -> Response<Full<Bytes>> {
        #[allow(clippy::expect_used)]
        Response::builder()
            .status(StatusCode::CONFLICT)
            .header(CONTENT_TYPE, "application/xml")
            .body(Full::new(Bytes::from(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>BucketNotEmpty</Code><Message>The bucket '{}' you tried to delete is not empty.</Message></Error>",
                bucket
            ))))
            .expect("Failed to generate a bucket not empty response")
    }

    fn no_such_bucket_response(&self, bucket: &str) -> Response<Full<Bytes>> {
        #[allow(clippy::expect_used)]
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(CONTENT_TYPE, "application/xml")
            .body(Full::new(Bytes::from(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>NoSuchBucket</Code><Message>The specified bucket '{}' does not exist.</Message></Error>",
                bucket
            ))))
            .expect("Failed to generate a no such bucket response")
    }

    fn invalid_bucket_name_response(&self, reason: &str) -> Response<Full<Bytes>> {
        #[allow(clippy::expect_used)]
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(CONTENT_TYPE, "application/xml")
            .body(Full::new(Bytes::from(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>InvalidBucketName</Code><Message>{}</Message></Error>",
                reason
            ))))
            .expect("Failed to generate an invalid bucket name response")
    }
}
