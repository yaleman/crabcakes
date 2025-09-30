use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::error::CrabCakesError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub access_key_id: String,
    pub secret_access_key: String,
}

pub struct CredentialStore {
    credentials: HashMap<String, Credential>,
}

impl CredentialStore {
    /// Create a new CredentialStore by loading credentials from the given directory
    pub fn new(credentials_dir: PathBuf) -> Result<Self, CrabCakesError> {
        let mut credentials = HashMap::new();

        info!(credentials_dir = ?credentials_dir, "Loading credentials");

        if !credentials_dir.exists() {
            warn!(credentials_dir = ?credentials_dir, "Credentials directory does not exist, starting with no credentials");
            return Ok(Self { credentials });
        }

        if !credentials_dir.is_dir() {
            error!(credentials_dir = ?credentials_dir, "Credentials path is not a directory");
            return Err(CrabCakesError::other(
                "Credentials path is not a directory",
            ));
        }

        // Read all JSON files from the credentials directory
        for entry in fs::read_dir(&credentials_dir)? {
            let entry = entry.inspect_err(|err| debug!("Failed to read {:?}", err))?;
            let path = entry.path();

            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                match Self::load_credential(&path) {
                    Ok(credential) => {
                        let access_key = credential.access_key_id.clone();
                        info!(access_key = %access_key, path = ?path, "Loaded credential");
                        credentials.insert(access_key, credential);
                    }
                    Err(e) => {
                        error!(path = ?path, error = %e, "Failed to load credential");
                    }
                }
            }
        }

        info!(count = credentials.len(), "Loaded credentials");
        Ok(Self { credentials })
    }

    /// Load a single credential from a JSON file
    fn load_credential(path: &PathBuf) -> Result<Credential, CrabCakesError> {
        let contents = fs::read_to_string(path)?;
        let credential: Credential = serde_json::from_str(&contents)?;
        Ok(credential)
    }

    /// Get a credential by access key ID
    pub fn get_credential(&self, access_key_id: &str) -> Option<&Credential> {
        self.credentials.get(access_key_id)
    }

    /// Get the secret access key for a given access key ID
    pub fn get_secret_key(&self, access_key_id: &str) -> Option<&str> {
        self.credentials
            .get(access_key_id)
            .map(|c| c.secret_access_key.as_str())
    }

    /// Get the number of loaded credentials
    pub fn credential_count(&self) -> usize {
        self.credentials.len()
    }
}