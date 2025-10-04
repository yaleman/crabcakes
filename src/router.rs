//! Request router for dispatching between S3 and web handlers

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};
use tower::Service;

use crate::s3_handlers::S3Handler;

/// Wrapped web service with session layer applied
pub type WebServiceWithSession =
    tower::util::BoxCloneService<Request<hyper::body::Incoming>, Response<Full<Bytes>>, Infallible>;

/// Routes requests to either S3 or web handlers based on path
pub async fn route_request(
    req: Request<hyper::body::Incoming>,
    remote_addr: SocketAddr,
    s3_handler: Arc<S3Handler>,
    web_service: Option<WebServiceWithSession>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();

    // Check if this is a web UI path
    let is_web_path = path == "/"
        || path.starts_with("/login")
        || path.starts_with("/logout")
        || path.starts_with("/oauth2/")
        || path.starts_with("/api/")
        || path.starts_with("/admin/")
        || path == "/admin";

    // Only route to web handler if it's configured AND this is a web path
    if is_web_path && web_service.is_some() {
        if let Some(mut service) = web_service {
            // Use the tower service with session layer
            service.call(req).await
        } else {
            // Should never happen due to is_some() check above
            Ok(Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("Service missing")))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Error")))))
        }
    } else {
        // S3 request (or web handler not configured) - handle with S3 handler
        s3_handler.handle_request(req, remote_addr).await
    }
}
