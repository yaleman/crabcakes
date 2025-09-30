use std::convert::Infallible;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Method, Request, Response, StatusCode};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use crate::filesystem::FilesystemService;
use crate::xml_responses::{ListBucketResponse, ListBucketsResponse};

pub struct S3Handler {
    filesystem: Arc<FilesystemService>,
}

impl S3Handler {
    pub fn new(filesystem: Arc<FilesystemService>) -> Self {
        Self {
            filesystem,
        }
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
        let method = req.method();
        let path = req.uri().path();
        let query = req.uri().query().unwrap_or("");
        let bucket_name = self.extract_bucket_name(&req);

        let response = match (method, path, query) {
            (&Method::GET, "/", query) if query.contains("list-type=2") => {
                self.handle_list_bucket(query, &bucket_name).await
            }
            (&Method::GET, "/", _) => self.handle_list_buckets(&bucket_name).await,
            (&Method::HEAD, key, _) if !key.is_empty() && key != "/" => {
                self.handle_head_object(&key[1..]).await
            }
            (&Method::GET, key, _) if !key.is_empty() && key != "/" => {
                self.handle_get_object(&key[1..]).await
            }
            _ => self.not_found_response(),
        };

        Ok(response)
    }

    async fn handle_list_bucket(&self, query: &str, bucket_name: &str) -> Response<Full<Bytes>> {
        let mut prefix = None;
        let mut max_keys = 1000;
        let mut continuation_token = None;

        for param in query.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                match key {
                    "prefix" => prefix = Some(value),
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

        match self
            .filesystem
            .list_directory(prefix, max_keys, continuation_token)
        {
            Ok((entries, next_token)) => {
                let response = ListBucketResponse::new(
                    bucket_name.to_string(),
                    prefix.unwrap_or("").to_string(),
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
                    Err(_) => self.internal_error_response(),
                }
            }
            Err(_) => self.internal_error_response(),
        }
    }

    async fn handle_list_buckets(&self, bucket_name: &str) -> Response<Full<Bytes>> {
        let response = ListBucketsResponse::new(bucket_name.to_string());

        match response.to_xml() {
            Ok(xml) => Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/xml")
                .header("Content-Length", xml.len())
                .body(Full::new(Bytes::from(xml)))
                .unwrap(),
            Err(_) => self.internal_error_response(),
        }
    }

    async fn handle_head_object(&self, key: &str) -> Response<Full<Bytes>> {
        match self.filesystem.get_file_metadata(key) {
            Ok(metadata) => Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", metadata.content_type)
                .header("Content-Length", metadata.size)
                .header("Last-Modified", metadata.last_modified.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
                .header("ETag", metadata.etag)
                .body(Full::new(Bytes::new()))
                .unwrap(),
            Err(_) => self.not_found_response(),
        }
    }

    async fn handle_get_object(&self, key: &str) -> Response<Full<Bytes>> {
        match self.filesystem.get_file_metadata(key) {
            Ok(metadata) => {
                match File::open(&metadata.path).await {
                    Ok(mut file) => {
                        let mut contents = Vec::new();
                        match file.read_to_end(&mut contents).await {
                            Ok(_) => Response::builder()
                                .status(StatusCode::OK)
                                .header("Content-Type", metadata.content_type)
                                .header("Content-Length", metadata.size)
                                .header("Last-Modified", metadata.last_modified.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
                                .header("ETag", metadata.etag)
                                .body(Full::new(Bytes::from(contents)))
                                .unwrap(),
                            Err(_) => self.internal_error_response(),
                        }
                    }
                    Err(_) => self.not_found_response(),
                }
            }
            Err(_) => self.not_found_response(),
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