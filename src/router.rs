//! Request router for dispatching between S3 and web handlers

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};
use tower::Service;

use crate::web::handlers::respond_500;
use crate::web::s3_handlers::S3Handler;

pub(crate) type WebServiceResponse = Response<Full<Bytes>>;

/// Wrapped web service with session layer applied
pub(crate) type WebServiceWithSession =
    tower::util::BoxCloneService<Request<hyper::body::Incoming>, WebServiceResponse, Infallible>;

/// Returns "OK"
fn healthcheck_response() -> WebServiceResponse {
    let mut response = Response::new(Full::new(Bytes::from("OK")));
    *response.status_mut() = hyper::StatusCode::OK;
    response
}

/// Routes requests to either S3 or web handlers based on path
pub async fn route_request(
    req: Request<hyper::body::Incoming>,
    remote_addr: SocketAddr,
    s3_handler: Arc<S3Handler>,
    web_service: Option<WebServiceWithSession>,
) -> Result<WebServiceResponse, Infallible> {
    let path = req.uri().path();

    if path == "/up" {
        return Ok(healthcheck_response());
    }

    // Check if this is a web UI path
    let is_web_path = path == "/"
        || path.starts_with("/login")
        || path.starts_with("/logout")
        || path.starts_with("/oauth2/")
        || path.starts_with("/api/")
        || path.starts_with("/admin/")
        || path == "/admin";

    #[cfg(test)]
    {
        if web_service.is_none() {
            // In test mode, if web service is not configured, treat all paths as S3 paths
            // This allows testing S3 functionality without web handler
            return s3_handler.handle_request(req, remote_addr).await;
        }
    }

    // Only route to web handler if it's configured AND this is a web path
    if is_web_path {
        if let Some(mut web_service) = web_service {
            web_service.call(req).await
        } else {
            Ok(respond_500(&"Web handler not configured"))
        }
    } else {
        // S3 request (or web handler not configured) - handle with S3 handler
        s3_handler.handle_request(req, remote_addr).await
    }
}
