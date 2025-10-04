//! AWS credential storage and management.
//!
//! Loads and manages AWS access key credentials from JSON files for signature verification.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
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
    credentials: Arc<RwLock<HashMap<String, String>>>,
    credentials_dir: PathBuf,
}

impl CredentialStore {
    /// Create a new CredentialStore by loading credentials from the given directory
    pub fn new(credentials_dir: &PathBuf) -> Result<Self, CrabCakesError> {
        let mut credentials = HashMap::new();

        info!(credentials_dir = ?credentials_dir, "Loading credentials");

        if !credentials_dir.exists() {
            warn!(credentials_dir = ?credentials_dir, "Credentials directory does not exist, starting with no credentials");
            return Ok(Self {
                credentials: Arc::new(RwLock::new(credentials)),
                credentials_dir: credentials_dir.clone(),
            });
        }

        if !credentials_dir.is_dir() {
            error!(credentials_dir = ?credentials_dir, "Credentials path is not a directory");
            return Err(CrabCakesError::other(
                &"Credentials path is not a directory",
            ));
        }

        // Read all JSON files from the credentials directory
        for entry in fs::read_dir(credentials_dir)? {
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
        Ok(Self {
            credentials: Arc::new(RwLock::new(credentials)),
            credentials_dir: credentials_dir.clone(),
        })
    }

    /// Get a credential by access key ID
    pub async fn get_credential(&self, access_key_id: &str) -> Option<String> {
        self.credentials.read().await.get(access_key_id).cloned()
    }

    /// Get the secret access key for a given access key ID
    pub async fn get_secret_key(&self, access_key_id: &str) -> Option<String> {
        self.credentials.read().await.get(access_key_id).cloned()
    }

    /// Get the number of loaded credentials
    pub async fn credential_count(&self) -> usize {
        self.credentials.read().await.len()
    }

    /// Get all access key IDs (NOT secret keys - for display purposes only)
    pub async fn get_access_key_ids(&self) -> Vec<String> {
        let credentials = self.credentials.read().await;
        let mut keys: Vec<String> = credentials.keys().cloned().collect();
        keys.sort();
        keys
    }

    /// Add a new credential
    pub async fn add_credential(
        &self,
        access_key_id: String,
        secret_access_key: String,
    ) -> Result<(), CrabCakesError> {
        // Validate access key ID (no path traversal)
        if access_key_id.contains("..") || access_key_id.contains('/') || access_key_id.contains('\\') {
            return Err(CrabCakesError::other(&"Invalid access key ID"));
        }

        // Validate secret key length (AWS standard is 40 characters)
        if secret_access_key.len() != 40 {
            return Err(CrabCakesError::other(&"Secret access key must be 40 characters"));
        }

        // Check if credential already exists
        {
            let credentials = self.credentials.read().await;
            if credentials.contains_key(&access_key_id) {
                return Err(CrabCakesError::other(&format!("Credential '{}' already exists", access_key_id)));
            }
        }

        // Write to file
        let credential_path = self.credentials_dir.join(format!("{}.json", access_key_id));
        let credential = Credential {
            access_key_id: access_key_id.clone(),
            secret_access_key: secret_access_key.clone(),
        };
        let credential_json = serde_json::to_string_pretty(&credential)?;
        fs::write(&credential_path, credential_json)?;

        // Update in-memory store
        {
            let mut credentials = self.credentials.write().await;
            credentials.insert(access_key_id.clone(), secret_access_key);
        }

        info!(access_key_id = %access_key_id, "Added credential");
        Ok(())
    }

    /// Update an existing credential
    pub async fn update_credential(
        &self,
        access_key_id: String,
        secret_access_key: String,
    ) -> Result<(), CrabCakesError> {
        // Validate access key ID (no path traversal)
        if access_key_id.contains("..") || access_key_id.contains('/') || access_key_id.contains('\\') {
            return Err(CrabCakesError::other(&"Invalid access key ID"));
        }

        // Validate secret key length (AWS standard is 40 characters)
        if secret_access_key.len() != 40 {
            return Err(CrabCakesError::other(&"Secret access key must be 40 characters"));
        }

        // Check if credential exists
        {
            let credentials = self.credentials.read().await;
            if !credentials.contains_key(&access_key_id) {
                return Err(CrabCakesError::other(&format!("Credential '{}' not found", access_key_id)));
            }
        }

        // Write to file
        let credential_path = self.credentials_dir.join(format!("{}.json", access_key_id));
        let credential = Credential {
            access_key_id: access_key_id.clone(),
            secret_access_key: secret_access_key.clone(),
        };
        let credential_json = serde_json::to_string_pretty(&credential)?;
        fs::write(&credential_path, credential_json)?;

        // Update in-memory store
        {
            let mut credentials = self.credentials.write().await;
            credentials.insert(access_key_id.clone(), secret_access_key);
        }

        info!(access_key_id = %access_key_id, "Updated credential");
        Ok(())
    }

    /// Delete a credential
    pub async fn delete_credential(&self, access_key_id: &str) -> Result<(), CrabCakesError> {
        // Validate access key ID (no path traversal)
        if access_key_id.contains("..") || access_key_id.contains('/') || access_key_id.contains('\\') {
            return Err(CrabCakesError::other(&"Invalid access key ID"));
        }

        // Check if credential exists
        {
            let credentials = self.credentials.read().await;
            if !credentials.contains_key(access_key_id) {
                return Err(CrabCakesError::other(&format!("Credential '{}' not found", access_key_id)));
            }
        }

        // Delete file
        let credential_path = self.credentials_dir.join(format!("{}.json", access_key_id));
        fs::remove_file(&credential_path)?;

        // Remove from in-memory store
        {
            let mut credentials = self.credentials.write().await;
            credentials.remove(access_key_id);
        }

        info!(access_key_id = %access_key_id, "Deleted credential");
        Ok(())
    }

    /// Create an empty credential store (for testing)
    #[cfg(test)]
    pub fn new_empty() -> Self {
        use std::env;
        let temp_dir = env::temp_dir().join("crabcakes_test_credentials");
        fs::create_dir_all(&temp_dir).ok();
        Self {
            credentials: Arc::new(RwLock::new(HashMap::new())),
            credentials_dir: temp_dir,
        }
    }

    /// Add a credential (for testing)
    #[cfg(test)]
    pub async fn add_credential_test(&self, access_key_id: String, secret_access_key: String) {
        let mut credentials = self.credentials.write().await;
        credentials.insert(access_key_id, secret_access_key);
    }
}
