//! Tower service wrapper for web handler with session support

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};
use tower::Service;
use tower_sessions::Session;

use crate::web::handlers::WebHandler;

/// Tower service that wraps WebHandler and provides session support
#[derive(Clone)]
pub struct WebService {
    web_handler: Arc<WebHandler>,
}

impl WebService {
    pub fn new(web_handler: Arc<WebHandler>) -> Self {
        Self { web_handler }
    }
}

impl Service<Request<hyper::body::Incoming>> for WebService {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<hyper::body::Incoming>) -> Self::Future {
        let handler = self.web_handler.clone();

        Box::pin(async move {
            // Extract session from request extensions (added by SessionManagerLayer)
            // Session should always be present if SessionManagerLayer is configured
            let session = match req.extensions().get::<Session>().cloned() {
                Some(s) => s,
                None => {
                    // Session not found - this should never happen if SessionManagerLayer is configured
                    return Ok(Response::builder()
                        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::new(Bytes::from("Session not configured")))
                        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Error")))));
                }
            };

            handler.handle_request(req, session).await
        })
    }
}
