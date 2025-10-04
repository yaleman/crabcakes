//! Request router for dispatching between S3 and web handlers

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};
use tower_sessions::SessionManagerLayer;

use crate::s3_handlers::S3Handler;
use crate::web_handlers::WebHandler;

/// Routes requests to either S3 or web handlers based on path
pub async fn route_request(
    req: Request<hyper::body::Incoming>,
    remote_addr: SocketAddr,
    s3_handler: Arc<S3Handler>,
    web_handler: Option<Arc<WebHandler>>,
    session_layer: Option<SessionManagerLayer<tower_sessions_sqlx_store::SqliteStore>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();

    // Check if this is a web UI path
    let is_web_path = path.starts_with("/login")
        || path.starts_with("/logout")
        || path.starts_with("/oauth2/")
        || path.starts_with("/api/")
        || path.starts_with("/admin/");

    // Only route to web handler if it's configured AND this is a web path
    if is_web_path && web_handler.is_some() {
        if let (Some(handler), Some(layer)) = (web_handler, session_layer) {
            // Create a session for this request
            // TODO: Actually integrate with session layer properly
            // For now, return a stub response
            let _ = (handler, layer);
            Ok(Response::builder()
                .status(hyper::StatusCode::NOT_IMPLEMENTED)
                .body(Full::new(Bytes::from("Web UI not yet fully wired up")))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Error")))))
        } else {
            // Web handler configured but session layer missing
            Ok(Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("Session layer missing")))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Error")))))
        }
    } else {
        // S3 request (or web handler not configured) - handle with S3 handler
        s3_handler.handle_request(req, remote_addr).await
    }
}
