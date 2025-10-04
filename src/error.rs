//! Centralized error types for the crabcakes S3 server.

use std::net::AddrParseError;

use iam_rs::EvaluationError;

#[derive(Debug)]
pub enum CrabCakesError {
    IamEvaluation(EvaluationError),
    Other(String),
    SerdeJson(serde_json::Error),
    Io(std::io::Error),
    Database(String),
    NoPolicies,
    NoAuthenticationSupplied(String),
    InvalidCredential,
    Rustls(String),
    Sigv4Verification(String),
    NoUserIdInPrincipal,
    OidcStateParameterExpired,
    OidcDiscovery(String),
    HttpResponseError(String),
    BucketNotFound(String),
    Configuration(String),
    Hyper(String),
    Reqwest(String),
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
        }
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
