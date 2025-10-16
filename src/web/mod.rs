use http::{Response, StatusCode};
use http_body_util::Full;
use hyper::body::Bytes;

pub(crate) mod handlers;
pub(crate) mod s3_handlers;
/// Serialization and deserialization utilities
pub(crate) mod serde;
pub(crate) mod service;
/// Web templates
pub(crate) mod templates;

pub(crate) fn response_body_status(body: Bytes, status: StatusCode) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(body));
    *res.status_mut() = status;
    res
}
