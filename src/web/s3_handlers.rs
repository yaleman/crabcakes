//! S3 API request handlers and routing.
//!
//! Implements AWS S3-compatible API operations including bucket and object management,
//! with signature verification and IAM authorization.

use std::convert::Infallible;
use std::str::FromStr;
use std::sync::Arc;

use http::HeaderValue;
use http::header::{
    ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, HOST, LAST_MODIFIED,
    LOCATION, RANGE, WWW_AUTHENTICATE,
};
use http::request::Parts;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Method, Request, Response, StatusCode};
use iam_rs::Decision;
use scratchstack_arn::Arn;
use scratchstack_aws_principal::{PrincipalIdentity, User};
use scratchstack_aws_signature::auth::SigV4AuthenticatorResponse;
use scratchstack_aws_signature::{
    GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, NO_ADDITIONAL_SIGNED_HEADERS,
    SignatureOptions, X_AMZ_CONTENT_SHA256, service_for_signing_key_fn,
    sigv4_validate_streaming_request,
};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::auth::{AuthContext, extract_bucket_and_key, http_method_to_s3_action, verify_sigv4};
use crate::body_buffer::BufferedBody;
use crate::constants::{
    AWS4_HMAC_SHA256, MOCK_ACCOUNT_ID, RESERVED_BUCKET_NAMES, S3, S3Action, TRACE_BUCKET,
    TRACE_COPY_SOURCE, TRACE_HAS_RANGE_HEADER, TRACE_KEY, TRACE_METHOD, TRACE_REMOTE_ADDR,
    TRACE_S3_ACTION, TRACE_STATUS_CODE, TRACE_URI, TRACE_USER, X_AMZ_DECODED_CONTENT_LENGTH,
};
use crate::credentials::CredentialStore;
use crate::db::DBService;
use crate::filesystem::FilesystemService;
use crate::multipart::MultipartManager;
use crate::policy::PolicyStore;
use crate::web::handlers::respond_404;
use crate::web::response_body_status;
use crate::web::xml_responses::{
    CompleteMultipartUploadRequest, CompleteMultipartUploadResponse, CopyObjectResponse,
    CopyPartResponse, DeleteError, DeleteRequest, DeleteResponse, DeletedObject,
    GetBucketLocationResponse, GetObjectAttributesResponse, GetObjectTaggingResponse,
    InitiateMultipartUploadResponse, ListAllMyBucketsResult, ListBucketResponse,
    ListBucketV1Response, ListMultipartUploadsResponse, ListPartsResponse, MultipartUploadItem,
    PartItem, Tag, TagSet, TaggingRequest, to_xml,
};

static CT_APPLICATION_XML: &str = "application/xml";

pub struct S3Handler {
    server_addr: String,
    filesystem: Arc<FilesystemService>,
    policy_store: Arc<PolicyStore>,
    credentials_store: Arc<CredentialStore>,
    multipart_manager: Arc<RwLock<MultipartManager>>,
    db_service: Arc<DBService>,
    region: String,
}

fn is_streaming_request(parts: &Parts) -> bool {
    if parts.headers.get(X_AMZ_DECODED_CONTENT_LENGTH).is_none() {
        debug!("{X_AMZ_DECODED_CONTENT_LENGTH} header not found, not a streaming request");
        return false;
    }
    if let Some(content_sha256) = parts.headers.get(X_AMZ_CONTENT_SHA256) {
        debug!("{X_AMZ_CONTENT_SHA256} header found");
        if let Ok(sha_str) = content_sha256.to_str() {
            if sha_str.starts_with("STREAMING-") {
                debug!("Detected streaming signature in request");
                return true;
            } else if sha_str == "UNSIGNED-PAYLOAD" {
                debug!("Detected unsigned payload in request");
                return true;
            }
        }
    }
    debug!("{X_AMZ_CONTENT_SHA256} and other streaming header checks failed.");
    false
}

impl S3Handler {
    pub fn new(
        filesystem: Arc<FilesystemService>,
        policy_store: Arc<PolicyStore>,
        credentials_store: Arc<CredentialStore>,
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
    /// Returns Ok with (parts, buffered_body, SigV4AuthenticatorResponse) or Err with error response
    #[instrument(level = "debug", skip_all)]
    async fn verify_and_buffer_request(
        &self,
        request: Request<hyper::body::Incoming>,
    ) -> Result<(Parts, BufferedBody, SigV4AuthenticatorResponse), Response<Full<Bytes>>> {
        // Extract the parts we need before consuming the request
        let (parts, body) = request.into_parts();

        // Check if this is a streaming/chunked request that needs decoding
        let needs_aws_chunk_decode =
            if let Some(content_sha256) = parts.headers.get(X_AMZ_CONTENT_SHA256) {
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

        debug!(x_amz_decoded_content_length = ?parts.headers.get(X_AMZ_DECODED_CONTENT_LENGTH), "Checking for {X_AMZ_DECODED_CONTENT_LENGTH} header");

        // Check if this is a streaming/chunked request
        let is_streaming = is_streaming_request(&parts);

        // Verify signature using appropriate method
        let (parts, authenticatorresponse) = if is_streaming {
            debug!("Using streaming signature verification");
            debug!(
                uri = %parts.uri,
                method = %parts.method,
                headers = ?parts.headers,
                "Streaming request details before verification"
            );

            let creds = self.credentials_store.credentials.clone();

            let get_signing_key_fn = move |req: GetSigningKeyRequest| {
                let creds = creds.clone();
                async move {
                    let creds_reader = creds.read().await;
                    if let Some(sec) = (*creds_reader).get(req.access_key()) {
                        let secret_key = KSecretKey::from_str(&sec.clone()).map_err(|err| {
                            error!(error=%err, "Failed to parse secret key");
                            tower::BoxError::from("Failed to parse secret key")
                        })?;

                        let signing_key =
                            secret_key.to_ksigning(req.request_date(), req.region(), req.service());
                        let principal = PrincipalIdentity::User(User::new(
                            "aws",
                            MOCK_ACCOUNT_ID,
                            "/",
                            req.access_key(),
                        )?);
                        Ok(GetSigningKeyResponse::builder()
                            .signing_key(signing_key)
                            .principal(vec![principal])
                            .build()?)
                    } else {
                        Err(tower::BoxError::from(format!(
                            "Access key ID not found: {}",
                            req.access_key()
                        )))
                    }
                }
            };
            let mut get_signing_key_svc = service_for_signing_key_fn(get_signing_key_fn);

            match sigv4_validate_streaming_request(
                parts,
                &self.region,
                S3,
                &mut get_signing_key_svc,
                chrono::Utc::now(),
                &NO_ADDITIONAL_SIGNED_HEADERS,
                SignatureOptions::default(),
            )
            .await
            {
                Ok((parts, _body, response)) => (parts, response),
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

            // Get the body as Vec<u8> for signature verification
            let body_vec = match buffered_body.to_vec().await {
                Ok(vec) => vec,
                Err(e) => {
                    error!(error = %e, "Failed to read buffered body");
                    return Err(self.internal_error_response());
                }
            };
            let http_request = http::Request::from_parts(normalized_parts, body_vec.clone());

            match verify_sigv4(
                http_request,
                self.credentials_store.clone(),
                self.db_service.clone(),
                &self.region,
            )
            .await
            {
                Ok((parts, _body, response)) => (parts, response),
                Err(e) => {
                    warn!(error = %e, "Signature verification failed");
                    return Err(self
                        .unauthorized_response(&format!("Signature verification failed: {}", e)));
                }
            }
        };

        debug!(
            authenticator_response = ?authenticatorresponse,
            "Request signature verified successfully",
        );

        Ok((parts, buffered_body, authenticatorresponse))
    }

    fn to_xml_response(xml: String) -> Response<Full<Bytes>> {
        let xml_length = xml.len();
        let mut res = Response::new(Full::new(Bytes::from(xml)));
        *res.status_mut() = StatusCode::OK;
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(CT_APPLICATION_XML));
        res.headers_mut().insert(CONTENT_LENGTH, xml_length.into());
        res
    }

    #[allow(clippy::too_many_arguments)]
    async fn check_auth(
        &self,
        is_bucket_operation: bool,
        method: Method,
        query: &str,
        s3_action: S3Action,
        bucket: Option<&str>,
        key: &str,
        extracted_key: Option<&str>,
        auth_context: &AuthContext,
    ) -> Option<Response<Full<Bytes>>> {
        // Check if this is a temporary credential (OAuth-based) - they get full access
        let is_temp_credential = if let Some(ref username) = auth_context.username {
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
            debug!(access_key = ?auth_context.username, "Temporary credential - granting full access");
        } else {
            // this means we bypass authorization for the deleteobjects operation because we have to check per-file permissions later
            trace!("Is bucket operation: {}", is_bucket_operation);
            // TODO: work out if this should check is_bucket_operation too
            if method == Method::POST && query == "delete" && key.is_empty() {
                debug!(
                    "Bypassing authorization for DeleteObjects operation - will check per-object permissions later"
                );
            } else {
                let iam_request =
                    match auth_context.build_iam_request(s3_action, bucket, extracted_key) {
                        Ok(req) => req,
                        Err(e) => {
                            error!(error = %e, "Failed to build IAM request");
                            return Some(self.internal_error_response());
                        }
                    };
                debug!(request = ?iam_request, "Evaluating IAM policy for request");

                match self.policy_store.evaluate_request(&iam_request).await {
                    Ok(Decision::Allow) => {
                        debug!("Authorization granted");
                    }
                    Ok(Decision::NotApplicable) | Ok(Decision::Deny) => {
                        warn!(
                            request = ?iam_request,
                            principal = ?iam_request.principal,
                            action = %s3_action,
                            "Authorization denied"
                        );
                        return Some(self.access_denied_response());
                    }
                    Err(e) => {
                        error!(error = %e, "Error evaluating policy");
                        return Some(self.internal_error_response());
                    }
                }
            }
        }
        None
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(method, uri, remote_addr, status_code, user, bucket, key)
    )]
    pub async fn handle_request(
        &self,
        req: Request<hyper::body::Incoming>,
        remote_addr: std::net::SocketAddr,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        // Verify signature and buffer body (or return error response)
        let (parts, mut buffered_body, authenticator_response) =
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

        // Build authentication context from verified request
        let auth_context = if let Some(principal) = authenticator_response.principal().first() {
            let user = match principal {
                PrincipalIdentity::User(user) => {
                    debug!(user_name=%user.user_name(), "Authenticated S3 request with user identity");
                    user
                }
                _ => {
                    error!("Authenticated S3 request with non-user identity");
                    return Ok(self.unauthorized_response(
                        "Only user identities are supported for S3 requests",
                    ));
                }
            };
            let arn = Arn::from(user);

            AuthContext {
                principal: iam_rs::Principal::Aws(iam_rs::PrincipalId::String(arn.to_string())),
                username: Some(user.user_name().to_string()),
            }
        } else {
            // Fallback to anonymous if signature not required
            debug!("No principal found in authenticator response, treating as anonymous");
            AuthContext {
                principal: iam_rs::Principal::Wildcard,
                username: None,
            }
        };

        // Parse path-style bucket requests: /bucket/ or /bucket/key
        let (is_bucket_operation, key) = self.parse_path(&path);
        let key = key.to_string();

        // Determine S3 action and resource for authorization
        let s3_action = match http_method_to_s3_action(&method, &path, &query, is_bucket_operation)
        {
            Some(val) => val,
            None => return Ok(respond_404()),
        };
        let (bucket, extracted_key) = extract_bucket_and_key(&path);

        // Use extracted bucket from path for path-style requests, fall back to host header
        let bucket_for_operation = match bucket.as_ref() {
            Some(val) => val.as_str(),
            None => {
                debug!(path=%path, bucket_name = bucket_name, "No bucket in path, using bucket from Host header if available");
                bucket_name.as_str()
            }
        };

        // Check if bucket name is excluded (reserved, hidden, or system directory)
        if !bucket_for_operation.is_empty() {
            // URL-decode the bucket name to handle encoded characters like %2B (+)
            let decoded_bucket = urlencoding::decode(bucket_for_operation)
                .unwrap_or(std::borrow::Cow::Borrowed(bucket_for_operation));

            if RESERVED_BUCKET_NAMES.contains(&decoded_bucket.as_ref()) {
                warn!(bucket = %decoded_bucket, "Request to reserved bucket name");
                return Ok(self.invalid_bucket_name_response(&format!(
                    "Bucket name '{}' is reserved and cannot be used",
                    decoded_bucket
                )));
            }
            if decoded_bucket.starts_with('.') {
                warn!(bucket = %decoded_bucket, "Request to hidden directory bucket name");
                return Ok(self.invalid_bucket_name_response(&format!(
                    "Bucket name '{}' cannot start with a dot",
                    decoded_bucket
                )));
            }
            if decoded_bucket.as_ref() == "lost+found" {
                warn!(bucket = %decoded_bucket, "Request to system directory bucket name");
                return Ok(self.invalid_bucket_name_response(&format!(
                    "Bucket name '{}' is a system directory and cannot be used",
                    decoded_bucket
                )));
            }
        }

        let response = if let Some(response) = self
            .check_auth(
                is_bucket_operation,
                method.clone(),
                &query,
                s3_action,
                bucket.as_deref(),
                &key,
                extracted_key.as_deref(),
                &auth_context,
            )
            .await
        {
            response
        } else {
            // auth has passed
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
            let has_list_v1_params = query.contains("prefix=")
                || query.contains("marker=")
                || query.contains("max-keys=");

            match (
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
                (&Method::GET, false, false, key, _)
                    if !key.is_empty() && upload_id_opt.is_some() =>
                {
                    let upload_id = upload_id_opt.as_deref().unwrap_or("");
                    debug!(key = %key, upload_id = %upload_id, "Handling ListParts request");
                    self.handle_list_parts(bucket_for_operation, key, upload_id)
                        .await
                }
                // POST /key?uploadId=X - CompleteMultipartUpload
                (&Method::POST, false, false, key, _)
                    if !key.is_empty() && upload_id_opt.is_some() =>
                {
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
                (&Method::GET, false, true, _, query)
                    if has_list_v1_params && !query.is_empty() =>
                {
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
                (&Method::PUT, false, false, key, _)
                    if !key.is_empty() && copy_source.is_some() =>
                {
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
            }
        };

        let span = tracing::Span::current();
        span.record(TRACE_METHOD, tracing::field::display(method));
        span.record(TRACE_URI, tracing::field::display(parts.uri));
        span.record(TRACE_BUCKET, tracing::field::display(&bucket_name));
        if let Some(copy_source) = copy_source {
            span.record(TRACE_COPY_SOURCE, tracing::field::display(copy_source));
        }
        span.record(TRACE_S3_ACTION, tracing::field::display(&s3_action));

        span.record(TRACE_REMOTE_ADDR, tracing::field::display(remote_addr));
        span.record(
            TRACE_HAS_RANGE_HEADER,
            tracing::field::display(parts.headers.contains_key("range")),
        );
        span.record(TRACE_KEY, tracing::field::display(&key));

        if !span.has_field(TRACE_STATUS_CODE) {
            span.record(
                TRACE_STATUS_CODE,
                tracing::field::display(response.status().as_u16()),
            );
        }

        span.record(
            TRACE_USER,
            tracing::field::display(auth_context.username.as_deref().unwrap_or("-")),
        );
        info!("S3 Request completed");

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
                    "prefix" => {
                        // URL-decode the prefix parameter
                        query_prefix = urlencoding::decode(value).ok().map(|s| s.into_owned())
                    }
                    "max-keys" => {
                        if let Ok(mk) = value.parse::<usize>() {
                            max_keys = mk.min(1000);
                        }
                    }
                    "continuation-token" => {
                        // URL-decode the continuation token
                        continuation_token = urlencoding::decode(value).ok().map(|s| s.into_owned())
                    }
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
            .list_directory(prefix.as_deref(), max_keys, continuation_token.as_deref())
            .await
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

                match to_xml(response) {
                    Ok(xml) => Self::to_xml_response(xml),
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
                    "prefix" => {
                        // URL-decode the prefix parameter
                        query_prefix = urlencoding::decode(value).ok().map(|s| s.into_owned())
                    }
                    "max-keys" => {
                        if let Ok(mk) = value.parse::<usize>() {
                            max_keys = mk.min(1000);
                        }
                    }
                    "marker" => {
                        // URL-decode the marker parameter
                        if let Some(query_marker) =
                            urlencoding::decode(value).ok().map(|s| s.into_owned())
                        {
                            marker = query_marker;
                        }
                    }
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
            .await
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

                match to_xml(response) {
                    Ok(xml) => Self::to_xml_response(xml),
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
        match self.filesystem.list_buckets().await {
            Ok(buckets) => {
                debug!(count = buckets.len(), "Listed buckets");
                let response = ListAllMyBucketsResult::from_buckets(buckets);

                match to_xml(response) {
                    Ok(xml) => Self::to_xml_response(xml),
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
        match self.filesystem.get_file_metadata(key).await {
            Ok(metadata) => {
                debug!(key = %key, size = metadata.size, "HeadObject success");

                let mut res = Response::new(Full::new(Bytes::new()));
                *res.status_mut() = StatusCode::OK;

                let headers = res.headers_mut();
                match HeaderValue::from_str(&metadata.content_type) {
                    Ok(hv) => {
                        headers.insert(CONTENT_TYPE, hv);
                    }
                    Err(e) => {
                        error!(key = %key, error = %e, "Invalid content type");
                        headers.insert(
                            CONTENT_TYPE,
                            HeaderValue::from_static("application/octet-stream"),
                        );
                    }
                }
                match HeaderValue::from_str(&metadata.size.to_string()) {
                    Ok(hv) => {
                        headers.insert(CONTENT_LENGTH, hv);
                    }
                    Err(e) => {
                        error!(key = %key, error = %e, "Invalid content length");
                    }
                }
                match HeaderValue::from_str(
                    &metadata
                        .last_modified
                        .format("%a, %d %b %Y %H:%M:%S GMT")
                        .to_string(),
                ) {
                    Ok(hv) => {
                        headers.insert(LAST_MODIFIED, hv);
                    }
                    Err(e) => {
                        error!(key = %key, error = %e, "Invalid Last-Modified header");
                    }
                }

                match HeaderValue::from_str(&metadata.etag) {
                    Ok(val) => {
                        headers.insert(ETAG, val);
                    }
                    Err(e) => {
                        error!(key = %key, error = %e, "Invalid ETag");
                    }
                };
                res
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
        let range_header = parts.headers.get(RANGE).and_then(|h| h.to_str().ok());
        self.handle_get_object_with_range(key, range_header).await
    }

    async fn handle_get_object_with_range(
        &self,
        key: &str,
        range_header: Option<&str>,
    ) -> Response<Full<Bytes>> {
        match self.filesystem.get_file_metadata(key).await {
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

                        let content_length = contents.len();

                        debug!(
                            key = %key,
                            is_range = is_range_request,
                            start = start,
                            end = end,
                            bytes_read = content_length,
                            metadata_size = metadata.size,
                            path = %metadata.path.display(),
                            "GetObject success"
                        );

                        let mut response = Response::new(Full::new(Bytes::from(contents)));
                        let response_headers = response.headers_mut();

                        match HeaderValue::from_str(&metadata.content_type) {
                            Ok(hv) => {
                                response_headers.insert(CONTENT_TYPE, hv);
                            }
                            Err(e) => {
                                error!(key = %key, error = %e, "Invalid content type, returning application/octet-stream");
                                response_headers.insert(
                                    CONTENT_TYPE,
                                    HeaderValue::from_static("application/octet-stream"),
                                );
                            }
                        }

                        if let Ok(lm) = HeaderValue::from_str(
                            &metadata
                                .last_modified
                                .format("%a, %d %b %Y %H:%M:%S GMT")
                                .to_string(),
                        ) {
                            response_headers.insert(LAST_MODIFIED, lm);
                        } else {
                            error!(ket = %key, "Failed to format Last-Modified header");
                            return self.internal_error_response();
                        }

                        if let Ok(etag) = HeaderValue::from_str(&metadata.etag) {
                            response_headers.insert(ETAG, etag);
                        } else {
                            error!(key = %key, "Invalid ETag");
                            return self.internal_error_response();
                        }

                        response_headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));

                        let status = if is_range_request {
                            response_headers.insert(CONTENT_LENGTH, content_length.into());

                            if let Ok(cr) = HeaderValue::from_str(&format!(
                                "bytes {}-{}/{}",
                                start, end, metadata.size
                            )) {
                                response_headers.insert(CONTENT_RANGE, cr);
                            } else {
                                error!(key = %key, "Failed to format Content-Range header");
                                return self.internal_error_response();
                            }
                            StatusCode::PARTIAL_CONTENT
                        } else {
                            response_headers
                                .insert(CONTENT_LENGTH, HeaderValue::from(metadata.size));
                            StatusCode::OK
                        };
                        *response.status_mut() = status;
                        response
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
        match self.filesystem.write_file(key, &body).await {
            Ok(metadata) => {
                debug!(key = %key, size = metadata.size, "PutObject success");
                let mut response = response_body_status(Bytes::new(), StatusCode::OK);
                if let Ok(hv) = HeaderValue::from_str(&metadata.etag) {
                    (*response.headers_mut()).insert(ETAG, hv);
                    response
                } else {
                    error!(key = %key, "Invalid ETag");
                    self.internal_error_response()
                }
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

                let mut res = response_body_status(Bytes::new(), StatusCode::OK);

                if let Ok(location) = HeaderValue::from_str(&format!("/{}", bucket)) {
                    res.headers_mut().insert(LOCATION, location);
                } else {
                    res.headers_mut()
                        .insert(LOCATION, HeaderValue::from_static("/"));
                };
                res
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
                if let Err(err) = self.db_service.delete_bucket_tags(bucket).await {
                    error!(bucket = %bucket, error = %err, "Failed to delete bucket tags from DB during DeleteBucket, will be cleaned up later");
                };

                debug!(bucket = %bucket, "DeleteBucket success");
                response_body_status(Bytes::new(), StatusCode::NO_CONTENT)
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
                response_body_status(Bytes::new(), StatusCode::NO_CONTENT)
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
                return response_body_status(
                    Bytes::from("Invalid XML request"),
                    StatusCode::BAD_REQUEST,
                );
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

        match to_xml(response) {
            Ok(xml) => Self::to_xml_response(xml),
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

        // permission on source
        let source_iam_request = match auth_context.build_iam_request(
            S3Action::GetObject,
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
            Ok(Decision::Allow) => {
                debug!("Authorization granted for source object");
            }
            Ok(Decision::Deny) | Ok(Decision::NotApplicable) => {
                warn!(
                    principal = ?source_iam_request.principal,
                    action = ?source_iam_request.action,
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

                match to_xml(response) {
                    Ok(xml) => Self::to_xml_response(xml),
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

        match to_xml(response) {
            Ok(xml) => Self::to_xml_response(xml),
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

            let mut res = response_body_status(Bytes::new(), StatusCode::OK);
            res.headers_mut().insert("x-amz-bucket-region", HeaderValue::from_str(&self.region).unwrap_or_else(|err| {
                error!(original_region = %self.region, error=%err,"Failed to parse region for x-amz-bucket-region header");
                HeaderValue::from_static("crabcakes")
        }));
            res
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
        if !self.filesystem.bucket_exists(bucket) {
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

                match to_xml(response) {
                    Ok(xml) => Self::to_xml_response(xml),
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

                let mut res = response_body_status(Bytes::new(), StatusCode::OK);
                if let Ok(etag) = HeaderValue::from_str(&part_info.etag) {
                    res.headers_mut().insert(ETAG, etag);
                    res
                } else {
                    error!(upload_id = %upload_id, part_number = %part_number, "Invalid ETag");
                    self.internal_error_response()
                }
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
            S3Action::GetObject,
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
            Ok(Decision::Allow) => {
                debug!("Authorization granted for source object");
            }
            Ok(Decision::Deny) | Ok(Decision::NotApplicable) => {
                warn!(
                    principal = ?source_iam_request.principal,
                    action = source_iam_request.action,
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
        let source_path = self.filesystem.resolve_path(source_key);
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
                            return response_body_status(
                                Bytes::from("Invalid range format"),
                                StatusCode::BAD_REQUEST,
                            );
                        }
                    };
                    let end: u64 = match end_str.parse() {
                        Ok(e) => e,
                        Err(_) => {
                            warn!(range = %range_str, "Invalid range format");
                            return response_body_status(
                                Bytes::from("Invalid range format"),
                                StatusCode::BAD_REQUEST,
                            );
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
                    return response_body_status(
                        Bytes::from("Invalid range format"),
                        StatusCode::BAD_REQUEST,
                    );
                }
            } else {
                warn!(range = %range_str, "Invalid range format - must start with bytes=");
                return response_body_status(
                    Bytes::from("Invalid range format"),
                    StatusCode::BAD_REQUEST,
                );
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

                let mut response = match to_xml(response) {
                    Ok(xml) => Self::to_xml_response(xml),
                    Err(e) => {
                        error!(error = %e, "Failed to serialize CopyPartResult XML");
                        return self.internal_error_response();
                    }
                };

                match HeaderValue::from_str(&part_info.etag) {
                    Ok(header) => {
                        response.headers_mut().insert(ETAG, header);
                        response
                    }
                    Err(err) => {
                        error!(bucket=&bucket, key=&key, error = %err, "Failed to set ETag header in handle_upload_part_copy response");
                        self.internal_error_response()
                    }
                }
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
                let mut res = Response::new(Full::new(Bytes::new()));
                *res.status_mut() = StatusCode::NO_CONTENT;
                res
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
        if !self.filesystem.bucket_exists(bucket) {
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

                match to_xml(response) {
                    Ok(xml) => Self::to_xml_response(xml),
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

                match to_xml(response) {
                    Ok(xml) => Self::to_xml_response(xml),
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

                    let mut res = Response::new(Full::new(Bytes::from("Invalid XML request")));
                    *res.status_mut() = StatusCode::BAD_REQUEST;
                    return res;
                }
            };

        // Extract parts as tuples (part_number, etag)
        let parts: Vec<(u32, String)> = complete_request
            .parts
            .into_iter()
            .map(|p| (p.part_number, p.etag))
            .collect();

        // Build full key path
        let dest_path = self.filesystem.resolve_path(key);

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

                match to_xml(response) {
                    Ok(xml) => Self::to_xml_response(xml),
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
                let mut res = Response::new(Full::new(Bytes::new()));
                *res.status_mut() = StatusCode::OK;
                res
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

                match to_xml(response) {
                    Ok(xml) => Self::to_xml_response(xml),
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
                let mut res = Response::new(Full::new(Bytes::new()));
                *res.status_mut() = StatusCode::NO_CONTENT;
                res
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
        let file_path = self.filesystem.resolve_path(file_key);

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

                match to_xml(response) {
                    Ok(xml) => Self::to_xml_response(xml),
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
        let mut res = Response::new(Full::new(Bytes::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>",
        )));
        *res.status_mut() = StatusCode::NOT_FOUND;
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(CT_APPLICATION_XML));
        res
    }

    fn access_denied_response(&self) -> Response<Full<Bytes>> {
        tracing::Span::current().record(TRACE_STATUS_CODE, tracing::field::display(403));
        let mut res = Response::new(Full::new(Bytes::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
        )));
        *res.status_mut() = StatusCode::FORBIDDEN;
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(CT_APPLICATION_XML));
        res
    }

    fn unauthorized_response(&self, reason: &str) -> Response<Full<Bytes>> {
        tracing::Span::current().record(TRACE_STATUS_CODE, tracing::field::display(401));
        let mut response = Response::new(Full::new(Bytes::from(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>InvalidAccessKeyId</Code><Message>{}</Message></Error>",
            reason
        ))));
        *response.status_mut() = StatusCode::UNAUTHORIZED;
        let headers = response.headers_mut();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(CT_APPLICATION_XML));
        headers.insert(WWW_AUTHENTICATE, HeaderValue::from_static(AWS4_HMAC_SHA256));
        response
    }

    fn internal_error_response(&self) -> Response<Full<Bytes>> {
        tracing::Span::current().record(TRACE_STATUS_CODE, tracing::field::display(500));
        let mut res = Response::new(Full::new(Bytes::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>InternalError</Code><Message>We encountered an internal error. Please try again.</Message></Error>",
        )));
        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(CT_APPLICATION_XML));
        res
    }

    fn bucket_already_exists_response(&self, bucket: &str) -> Response<Full<Bytes>> {
        tracing::Span::current().record(TRACE_STATUS_CODE, tracing::field::display(409));
        let mut res = Response::new(Full::new(Bytes::from(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>BucketAlreadyExists</Code><Message>The requested bucket name '{}' is not available.</Message></Error>",
            bucket
        ))));
        *res.status_mut() = StatusCode::CONFLICT;
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(CT_APPLICATION_XML));
        res
    }

    fn bucket_not_empty_response(&self, bucket: &str) -> Response<Full<Bytes>> {
        tracing::Span::current().record(TRACE_STATUS_CODE, tracing::field::display(409));
        let mut res = Response::new(Full::new(Bytes::from(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>BucketNotEmpty</Code><Message>The bucket '{}' you tried to delete is not empty.</Message></Error>",
            bucket
        ))));
        *res.status_mut() = StatusCode::CONFLICT;
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(CT_APPLICATION_XML));
        res
    }

    fn no_such_bucket_response(&self, bucket: &str) -> Response<Full<Bytes>> {
        tracing::Span::current().record(TRACE_STATUS_CODE, tracing::field::display(404));
        let mut res = Response::new(Full::new(Bytes::from(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>NoSuchBucket</Code><Message>The specified bucket '{}' does not exist.</Message></Error>",
            bucket
        ))));
        *res.status_mut() = StatusCode::NOT_FOUND;
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(CT_APPLICATION_XML));
        res
    }

    fn invalid_bucket_name_response(&self, reason: &str) -> Response<Full<Bytes>> {
        let mut response = Response::new(Full::new(Bytes::from(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>InvalidBucketName</Code><Message>{}</Message></Error>",
            reason
        ))));
        *response.status_mut() = StatusCode::BAD_REQUEST;
        tracing::Span::current().record(
            TRACE_STATUS_CODE,
            tracing::field::display(StatusCode::BAD_REQUEST.as_u16()),
        );
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(CT_APPLICATION_XML));

        response
    }
}
