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

impl TryFrom<&PathBuf> for Credential {
    type Error = CrabCakesError;

    fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
        let contents = fs::read_to_string(path)?;
        let credential: Credential = serde_json::from_str(&contents)?;
        Ok(credential)
    }
}

pub struct CredentialStore {
    credentials: HashMap<String, String>,
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
            return Err(CrabCakesError::other("Credentials path is not a directory"));
        }

        // Read all JSON files from the credentials directory
        for entry in fs::read_dir(&credentials_dir)? {
            let entry = entry.inspect_err(|err| debug!("Failed to read {:?}", err))?;
            let path = entry.path();

            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                let credential = Credential::try_from(&path).inspect_err(
                    |e| error!(path = ?path, error = %e, "Failed to load credential"),
                )?;

                if credential.secret_access_key.len() != 40 {
                    error!(access_key = %credential.access_key_id, err="Secret length is not 40 characters, this is an invalid key, ignoring!");
                    continue;
                }

                debug!(access_key = %credential.access_key_id, path = ?path, "Loaded credential");
                credentials.insert(credential.access_key_id, credential.secret_access_key);
            }
        }

        info!(loaded_credentials_count = credentials.len());
        if credentials.is_empty() {
            error!("No credentials loaded, server will not authenticate requests");
        }
        Ok(Self { credentials })
    }

    /// Get a credential by access key ID
    pub fn get_credential(&self, access_key_id: &str) -> Option<&String> {
        self.credentials.get(access_key_id)
    }

    /// Get the secret access key for a given access key ID
    pub fn get_secret_key(&self, access_key_id: &str) -> Option<&str> {
        self.credentials.get(access_key_id).map(|c| c.as_str())
    }

    /// Get the number of loaded credentials
    pub fn credential_count(&self) -> usize {
        self.credentials.len()
    }
}
