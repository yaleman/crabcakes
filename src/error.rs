//! Centralized error types for the crabcakes S3 server.

use std::{error::Error, net::AddrParseError, path::PathBuf};

use askama::Template;
use http::{
    HeaderValue, Response, StatusCode,
    header::{CONTENT_TYPE, InvalidHeaderValue},
};
use http_body_util::Full;
use hyper::body::Bytes;
use iam_rs::EvaluationError;
use mime_guess::mime::TEXT_HTML_UTF_8;
use scratchstack_aws_signature::{SignatureError, auth::SigV4AuthenticatorResponseBuilderError};
use serde::Serialize;
use serde_with::{DisplayFromStr, serde_as};

use crate::web::templates::ErrorTemplate;

#[serde_as]
#[derive(Serialize, Debug)]
pub enum CrabCakesError {
    BucketNotFound(String),
    FileNotFound(PathBuf),
    Configuration(String),
    CredentialAlreadyExists,
    Database(String),
    HttpResponseError(String),
    Hyper(String),
    IamEvaluation(#[serde_as(as = "DisplayFromStr")] EvaluationError),
    InvalidAccessKeyId,
    InvalidBucketName,
    InvalidCredential,
    InvalidPath,
    InvalidPolicyName,
    InvalidSecretLength,
    Io(#[serde_as(as = "DisplayFromStr")] std::io::Error),
    NoAuthenticationSupplied(String),
    NoPolicies,
    NoUserIdInPrincipal,
    OidcDiscovery(String),
    OidcStateParameterExpired,
    Other(String),
    Reqwest(String),
    Rustls(String),
    SerdeJson(#[serde_as(as = "DisplayFromStr")] serde_json::Error),
    SigV4AuthenticatorResponseBuilderError(String),
    Sigv4Verification(String),
    TemplateRendering(String),
    UnknownAction,
}

impl std::fmt::Display for CrabCakesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrabCakesError::IamEvaluation(e) => write!(f, "IAM Evaluation Error: {}", e),
            CrabCakesError::Other(msg) => write!(f, "Error: {}", msg),
            CrabCakesError::SerdeJson(e) => write!(f, "Serde-JSON Error: {}", e),
            CrabCakesError::Io(e) => write!(f, "IO Error: {:?}", e),
            CrabCakesError::Database(msg) => write!(f, "Database Error: {}", msg),
            CrabCakesError::NoPolicies => write!(f, "No IAM policies found"),
            CrabCakesError::NoAuthenticationSupplied(msg) => {
                write!(f, "No Authentication Supplied: {}", msg)
            }
            CrabCakesError::InvalidCredential => write!(f, "Invalid credential identifier"),
            CrabCakesError::Rustls(msg) => write!(f, "Rustls Error: {}", msg),
            CrabCakesError::Sigv4Verification(msg) => {
                write!(f, "SigV4 Verification Error: {}", msg)
            }
            CrabCakesError::NoUserIdInPrincipal => {
                write!(f, "No User ID found in principal")
            }
            CrabCakesError::OidcStateParameterExpired => {
                write!(f, "OIDC state parameter expired")
            }
            CrabCakesError::HttpResponseError(msg) => {
                write!(f, "HTTP Response Error: {}", msg)
            }
            CrabCakesError::BucketNotFound(bucket) => {
                write!(f, "Bucket '{bucket}' Not Found")
            }
            CrabCakesError::Configuration(msg) => {
                write!(f, "Configuration Error: {}", msg)
            }
            CrabCakesError::Hyper(msg) => {
                write!(f, "Hyper HTTP Error: {}", msg)
            }
            CrabCakesError::Reqwest(msg) => {
                write!(f, "Reqwest HTTP Error: {}", msg)
            }
            CrabCakesError::OidcDiscovery(msg) => {
                write!(f, "OIDC Discovery Error: {}", msg)
            }
            CrabCakesError::CredentialAlreadyExists => {
                write!(f, "Credential with the same identifier already exists")
            }
            CrabCakesError::SigV4AuthenticatorResponseBuilderError(msg) => {
                write!(f, "SigV4AuthenticatorResponse Builder Error: {}", msg)
            }
            CrabCakesError::TemplateRendering(msg) => {
                write!(f, "Template Rendering Error: {}", msg)
            }
            CrabCakesError::UnknownAction => {
                f.write_str("Could not identify S3 Action for Request")
            }
            CrabCakesError::InvalidPath => f.write_str("Invalid path"),
            CrabCakesError::InvalidPolicyName => f.write_str("Invalid policy name"),
            CrabCakesError::InvalidAccessKeyId => f.write_str("Invalid Access Key ID"),
            CrabCakesError::InvalidSecretLength => {
                f.write_str("Invalid Secret Length, should be 40 characters")
            }
            CrabCakesError::InvalidBucketName => f.write_str("Invalid Bucket Name"),
            CrabCakesError::FileNotFound(path) => {
                write!(f, "File not found: {}", path.display())
            }
        }
    }
}

impl From<InvalidHeaderValue> for CrabCakesError {
    fn from(err: InvalidHeaderValue) -> Self {
        CrabCakesError::Other(err.to_string())
    }
}

impl From<askama::Error> for CrabCakesError {
    fn from(err: askama::Error) -> Self {
        CrabCakesError::TemplateRendering(err.to_string())
    }
}

impl From<Box<dyn Error + Send + Sync>> for CrabCakesError {
    fn from(err: Box<dyn Error + Send + Sync>) -> Self {
        CrabCakesError::Other(err.to_string())
    }
}

impl From<iam_rs::ArnError> for CrabCakesError {
    fn from(err: iam_rs::ArnError) -> Self {
        CrabCakesError::Other(format!("Failed to parse ARN: {}", err))
    }
}

impl From<chrono::ParseError> for CrabCakesError {
    fn from(err: chrono::ParseError) -> Self {
        CrabCakesError::Other(format!("Failed to parse date: {}", err))
    }
}

impl From<SignatureError> for CrabCakesError {
    fn from(err: SignatureError) -> Self {
        CrabCakesError::Sigv4Verification(err.to_string())
    }
}

impl From<SigV4AuthenticatorResponseBuilderError> for CrabCakesError {
    fn from(err: SigV4AuthenticatorResponseBuilderError) -> Self {
        CrabCakesError::SigV4AuthenticatorResponseBuilderError(err.to_string())
    }
}

impl From<reqwest::Error> for CrabCakesError {
    fn from(err: reqwest::Error) -> Self {
        CrabCakesError::Reqwest(err.to_string())
    }
}

impl From<hyper::Error> for CrabCakesError {
    fn from(err: hyper::Error) -> Self {
        CrabCakesError::Hyper(err.to_string())
    }
}

impl From<http::Error> for CrabCakesError {
    fn from(err: http::Error) -> Self {
        CrabCakesError::HttpResponseError(err.to_string())
    }
}

impl From<rustls::Error> for CrabCakesError {
    fn from(err: rustls::Error) -> Self {
        CrabCakesError::Rustls(err.to_string())
    }
}

impl From<serde_json::Error> for CrabCakesError {
    fn from(err: serde_json::Error) -> Self {
        CrabCakesError::SerdeJson(err)
    }
}

impl From<std::io::Error> for CrabCakesError {
    fn from(err: std::io::Error) -> Self {
        CrabCakesError::Io(err)
    }
}

impl From<EvaluationError> for CrabCakesError {
    fn from(err: EvaluationError) -> Self {
        CrabCakesError::IamEvaluation(err)
    }
}

impl From<AddrParseError> for CrabCakesError {
    fn from(err: AddrParseError) -> Self {
        CrabCakesError::Other(err.to_string())
    }
}

impl From<sea_orm::DbErr> for CrabCakesError {
    fn from(err: sea_orm::DbErr) -> Self {
        CrabCakesError::Database(err.to_string())
    }
}

impl From<CrabCakesError> for Box<dyn std::error::Error + Send + Sync> {
    fn from(val: CrabCakesError) -> Self {
        Box::new(std::io::Error::other(val.to_string()))
    }
}

impl CrabCakesError {
    pub fn other(error: &impl ToString) -> Self {
        CrabCakesError::Other(error.to_string())
    }
}

impl From<CrabCakesError> for Response<Full<Bytes>> {
    fn from(err: CrabCakesError) -> Response<Full<Bytes>> {
        let template = ErrorTemplate {
            error_message: err.to_string(),
        };

        let html = match template.render() {
            Ok(html) => html,
            Err(e) => {
                #[allow(clippy::panic)]
                {
                    #[cfg(any(test, debug_assertions))]
                    panic!("Failed to render error template! {}", e);
                }
                #[cfg(not(any(test, debug_assertions)))]
                format!(
                    "<html><body><h1>Error</h1><p>Failed to render error template: {}</p><p>Original error: {}</p></body></html>",
                    e, err
                )
            }
        };

        let mut res = Response::new(Full::new(Bytes::from(html)));

        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        (*res.headers_mut()).append(
            CONTENT_TYPE,
            HeaderValue::from_static(TEXT_HTML_UTF_8.as_ref()),
        );
        res
    }
}
