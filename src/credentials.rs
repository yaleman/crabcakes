//! AWS credential storage and management.
//!
//! Loads and manages AWS access key credentials from JSON files for signature verification.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::{constants::SECRET_ACCESS_KEY_LENGTH, error::CrabCakesError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    access_key_id: String,
    secret_access_key: String,
}

impl TryFrom<(&str, &str)> for Credential {
    type Error = CrabCakesError;

    fn try_from(input: (&str, &str)) -> Result<Self, CrabCakesError> {
        let (access_key_id, secret_access_key) = input;
        if secret_access_key.len() != SECRET_ACCESS_KEY_LENGTH {
            return Err(CrabCakesError::InvalidSecretLength);
        }

        if access_key_id.contains("..")
            || access_key_id.contains('/')
            || access_key_id.contains('\\')
        {
            return Err(CrabCakesError::InvalidAccessKeyId);
        }

        Ok(Self {
            access_key_id: access_key_id.to_string(),
            secret_access_key: secret_access_key.to_string(),
        })
    }
}

impl Credential {
    async fn async_try_from(path: &PathBuf) -> Result<Self, CrabCakesError> {
        let contents = fs::read_to_string(path).await?;
        let credential: Credential = serde_json::from_str(&contents)?;
        // this also implements name checks
        Credential::try_from((
            credential.access_key_id.as_ref(),
            credential.secret_access_key.as_ref(),
        ))
    }
}

pub struct CredentialStore {
    pub(crate) credentials: Arc<RwLock<HashMap<String, String>>>,
    credentials_dir: PathBuf,
}

impl CredentialStore {
    /// Create a new CredentialStore by loading credentials from the given directory
    pub async fn new(credentials_dir: &PathBuf) -> Result<Self, CrabCakesError> {
        let mut credentials = HashMap::new();

        info!(credentials_dir = ?credentials_dir, "Loading credentials");

        if !credentials_dir.exists() {
            warn!(credentials_dir = ?credentials_dir, "Credentials directory does not exist, starting with no credentials");
            fs::create_dir_all(credentials_dir)
                .await
                .inspect_err(|err| {
                    error!(
                        credentials_dir = ?credentials_dir,
                        error = %err,
                        "Failed to create credentials directory"
                    )
                })?;
            return Ok(Self {
                credentials: Arc::new(RwLock::new(credentials)),
                credentials_dir: credentials_dir.clone(),
            });
        }

        if !credentials_dir.is_dir() {
            error!(credentials_dir = ?credentials_dir, "Credentials path is not a directory");
            return Err(CrabCakesError::InvalidPath);
        }
        let mut dir_entries = fs::read_dir(credentials_dir).await.inspect_err(|err| {
            error!(
                credentials_dir = ?credentials_dir,
                error = %err,
                "Failed to read credentials directory"
            )
        })?;
        // Read all JSON files from the credentials directory
        while let Ok(Some(entry)) = dir_entries.next_entry().await {
            let path = entry.path();

            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                let credential = Credential::async_try_from(&path).await.inspect_err(
                    |e| error!(path = ?path, error = %e, "Failed to load credential"),
                )?;

                if credential.secret_access_key.len() != SECRET_ACCESS_KEY_LENGTH {
                    error!(access_key = %credential.access_key_id, err="Secret length is not {SECRET_ACCESS_KEY_LENGTH} characters, this is an invalid key, ignoring!");
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

    pub(crate) fn credential_path(&self, credential_name: &str) -> Result<PathBuf, CrabCakesError> {
        let res = self
            .credentials_dir
            .join(format!("{}.json", credential_name));
        if !res.starts_with(&self.credentials_dir) {
            error!(
                "Attempted path traversal in credential access: {}",
                credential_name
            );
            return Err(CrabCakesError::InvalidPath);
        }
        Ok(res)
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
    pub async fn write_credential(
        &self,
        access_key_id: String,
        secret_access_key: String,
    ) -> Result<(), CrabCakesError> {
        // Validate access key ID (no path traversal)
        if access_key_id.contains("..")
            || access_key_id.contains('/')
            || access_key_id.contains('\\')
        {
            return Err(CrabCakesError::InvalidAccessKeyId);
        }

        // Validate secret key length (AWS standard is 40 characters)
        if secret_access_key.len() != SECRET_ACCESS_KEY_LENGTH {
            return Err(CrabCakesError::InvalidSecretLength);
        }

        // Check if credential already exists
        {
            let credentials = self.credentials.read().await;
            if credentials.contains_key(&access_key_id) {
                debug!(access_key_id = access_key_id, "CredentialAlreadyExists");
                return Err(CrabCakesError::CredentialAlreadyExists);
            }
        }

        // Write to file
        let credential_path = self.credential_path(&access_key_id)?;
        let credential =
            Credential::try_from((access_key_id.as_ref(), secret_access_key.as_ref()))?;
        fs::write(&credential_path, serde_json::to_string_pretty(&credential)?).await?;

        // Update in-memory store
        {
            let mut credentials = self.credentials.write().await;
            credentials.insert(access_key_id.clone(), secret_access_key.clone());
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
        // Check if credential exists
        {
            let credentials = self.credentials.read().await;
            if !credentials.contains_key(&access_key_id) {
                return Err(CrabCakesError::other(&format!(
                    "Credential '{}' not found",
                    access_key_id
                )));
            }
        }
        let credential =
            Credential::try_from((access_key_id.as_ref(), secret_access_key.as_ref()))?;

        // Write to file
        fs::write(
            &self.credential_path(&access_key_id)?,
            serde_json::to_string_pretty(&credential)?,
        )
        .await?;

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
        // Check if credential exists
        {
            let mut credentials = self.credentials.write().await;

            if credentials.remove(access_key_id).is_some() {
                debug!(access_key_id = %access_key_id, "Removed credential from memory");
            } else {
                debug!(access_key_id = %access_key_id, "Credential not found in memory");
            }
        }

        // Delete file
        let cred_path = &self.credential_path(access_key_id)?;
        if cred_path.exists() {
            fs::remove_file(cred_path).await?;
        } else {
            debug!("Credential file does not exist: {:?}", cred_path);
        }

        info!(access_key_id = %access_key_id, "Deleted credential");
        Ok(())
    }

    /// Create an empty credential store (for testing)
    #[cfg(test)]
    pub async fn new_test() -> Arc<RwLock<Self>> {
        let random_number = rand::random::<u32>();
        let temp_dir =
            std::env::temp_dir().join(format!("crabcakes_test_credentials{random_number}"));
        fs::create_dir_all(&temp_dir).await.ok();
        Arc::new(RwLock::new(Self {
            credentials: Arc::new(RwLock::new(HashMap::new())),
            credentials_dir: temp_dir,
        }))
    }
}
