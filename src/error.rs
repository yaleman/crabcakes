use iam_rs::EvaluationError;

#[derive(Debug)]
pub enum CrabCakesError {
    IamEvaluation(EvaluationError),
    Other(String),
    SerdeJson(serde_json::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for CrabCakesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrabCakesError::IamEvaluation(e) => write!(f, "IAM Evaluation Error: {}", e),
            CrabCakesError::Other(msg) => write!(f, "Error: {}", msg),
            CrabCakesError::SerdeJson(e) => write!(f, "Serde-JSON Error: {}", e),
            CrabCakesError::Io(e) => write!(f, "IO Error: {:?}", e),
        }
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

impl CrabCakesError {
    pub fn other(error: impl ToString) -> Self {
        CrabCakesError::Other(error.to_string())
    }
}
