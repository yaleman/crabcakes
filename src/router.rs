//! Request router for dispatching between S3 and web handlers

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::AUTHORIZATION;
use hyper::{Request, Response};
use tower::Service;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::trace::ResponseBody;

use crate::web::handlers::respond_500;
use crate::web::s3_handlers::S3Handler;

/// BoxBody type that can handle any response body - using Box<dyn Error> for maximum flexibility
pub(crate) type BoxBody =
    http_body_util::combinators::BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

pub(crate) type WebServiceResponse = Response<BoxBody>;

/// Response body type after TraceLayer is applied
pub(crate) type TracedResponseBody =
    ResponseBody<Full<Bytes>, tower_http::classify::NeverClassifyEos<ServerErrorsFailureClass>>;

/// Wrapped web service with session layer and tracing applied
pub(crate) type WebServiceWithSession = tower::util::BoxCloneService<
    Request<hyper::body::Incoming>,
    Response<TracedResponseBody>,
    Infallible,
>;

/// Returns "OK"
fn healthcheck_response() -> WebServiceResponse {
    let mut response = Response::new(
        Full::new(Bytes::from("OK"))
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            .boxed(),
    );
    *response.status_mut() = hyper::StatusCode::OK;
    response
}

fn is_web_request<B>(request: &Request<B>) -> bool {
    let path = request.uri().path();
    let is_signed_root = path == "/"
        && request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 "));

    !is_signed_root
        && (path == "/"
            || path.starts_with("/login")
            || path.starts_with("/logout")
            || path.starts_with("/oauth2/")
            || path.starts_with("/api/")
            || path.starts_with("/admin/")
            || path == "/admin")
}

/// Routes requests to either S3 or web handlers based on path
pub async fn route_request(
    req: Request<hyper::body::Incoming>,
    remote_addr: SocketAddr,
    s3_handler: Arc<S3Handler>,
    web_service: Option<WebServiceWithSession>,
) -> Result<WebServiceResponse, Infallible> {
    let start_time = Utc::now();
    let path = req.uri().path();

    if path == "/up" {
        return Ok(healthcheck_response());
    }

    // Signed requests to the root are S3 ListBuckets requests, not web UI requests.
    let is_web_path = is_web_request(&req);

    #[cfg(test)]
    {
        if web_service.is_none() {
            // In test mode, if web service is not configured, treat all paths as S3 paths
            // This allows testing S3 functionality without web handler
            let response = s3_handler
                .handle_request(req, remote_addr, start_time)
                .await?;
            let (parts, body) = response.into_parts();
            return Ok(Response::from_parts(
                parts,
                body.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
                    .boxed(),
            ));
        }
    }

    // Only route to web handler if it's configured AND this is a web path
    if is_web_path {
        if let Some(mut web_service) = web_service {
            // Call web service and convert TracedResponseBody to BoxBody
            let response = web_service.call(req).await?;
            let (parts, body) = response.into_parts();
            Ok(Response::from_parts(
                parts,
                body.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
                    .boxed(),
            ))
        } else {
            let response = respond_500(&"Web handler not configured");
            let (parts, body) = response.into_parts();
            Ok(Response::from_parts(
                parts,
                body.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
                    .boxed(),
            ))
        }
    } else {
        // S3 request (or web handler not configured) - handle with S3 handler
        let response = s3_handler
            .handle_request(req, remote_addr, start_time)
            .await?;
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            body.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
                .boxed(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use hyper::Request;
    use hyper::header::AUTHORIZATION;

    use super::is_web_request;

    #[test]
    fn signed_root_request_is_routed_to_s3() {
        let request = Request::builder()
            .uri("/")
            .header(
                AUTHORIZATION,
                "AWS4-HMAC-SHA256 Credential=test/20260620/crabcakes/s3/aws4_request",
            )
            .body(())
            .expect("request should build");

        assert!(!is_web_request(&request));
    }

    #[test]
    fn non_sigv4_authorization_on_root_is_routed_to_web_ui() {
        for authorization in [
            "Basic dXNlcjpwYXNz",
            "Bearer token",
            "",
            "AWS4-HMAC-SHA256",
            "not-an-authorization-scheme",
        ] {
            let request = Request::builder()
                .uri("/")
                .header(AUTHORIZATION, authorization)
                .body(())
                .expect("request should build");

            assert!(
                is_web_request(&request),
                "{authorization:?} should not be treated as SigV4"
            );
        }
    }

    #[test]
    fn unsigned_root_request_is_routed_to_web_ui() {
        let request = Request::builder()
            .uri("/")
            .body(())
            .expect("request should build");

        assert!(is_web_request(&request));
    }
}
