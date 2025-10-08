//! Database service providing business logic for all database operations

use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, Order, QueryFilter, QueryOrder,
    Set,
};
use std::sync::Arc;
use tracing::{debug, error};

use super::entities::{oauth_pkce_state, object_tags, temporary_credentials};
use crate::{constants::MAX_TEMP_CREDS_DURATION, error::CrabCakesError};

const MAX_TAGS: usize = 10;
const MAX_KEY_LENGTH: usize = 128;
const MAX_VALUE_LENGTH: usize = 256;

/// Database service for all metadata operations
pub struct DBService {
    db: Arc<DatabaseConnection>,
}

impl DBService {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }

    // ===== Tag Operations =====

    fn validate_tags(&self, tags: &[(String, String)]) -> Result<(), CrabCakesError> {
        if tags.len() > MAX_TAGS {
            return Err(CrabCakesError::other(&format!(
                "Too many tags: maximum {} allowed",
                MAX_TAGS
            )));
        }

        for (key, value) in tags {
            if key.is_empty() {
                return Err(CrabCakesError::other(&String::from(
                    "Tag key cannot be empty",
                )));
            }
            if key.len() > MAX_KEY_LENGTH {
                return Err(CrabCakesError::other(&format!(
                    "Tag key too long: maximum {} characters",
                    MAX_KEY_LENGTH
                )));
            }
            if value.len() > MAX_VALUE_LENGTH {
                return Err(CrabCakesError::other(&format!(
                    "Tag value too long: maximum {} characters",
                    MAX_VALUE_LENGTH
                )));
            }
        }

        Ok(())
    }

    pub async fn put_tags(
        &self,
        bucket: &str,
        key: &str,
        tags: Vec<(String, String)>,
    ) -> Result<(), CrabCakesError> {
        self.validate_tags(&tags)?;

        // Delete existing tags
        self.delete_tags(bucket, key).await?;

        // Insert new tags
        let now = chrono::Utc::now();
        for (tag_key, tag_value) in tags {
            let tag = object_tags::ActiveModel {
                bucket: Set(bucket.to_string()),
                key: Set(key.to_string()),
                tag_key: Set(tag_key),
                tag_value: Set(tag_value),
                created_at: Set(now),
                ..Default::default()
            };
            tag.insert(&*self.db).await?;
        }

        debug!(bucket = %bucket, key = %key, "Tags stored successfully");
        Ok(())
    }

    pub async fn get_tags(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Vec<(String, String)>, CrabCakesError> {
        let tags = object_tags::Entity::find()
            .filter(object_tags::Column::Bucket.eq(bucket))
            .filter(object_tags::Column::Key.eq(key))
            .all(&*self.db)
            .await?;

        Ok(tags.into_iter().map(|t| (t.tag_key, t.tag_value)).collect())
    }

    pub async fn delete_tags(&self, bucket: &str, key: &str) -> Result<(), CrabCakesError> {
        let result = object_tags::Entity::delete_many()
            .filter(object_tags::Column::Bucket.eq(bucket))
            .filter(object_tags::Column::Key.eq(key))
            .exec(&*self.db)
            .await?;

        debug!(
            bucket = %bucket,
            key = %key,
            rows_deleted = result.rows_affected,
            "Tags deleted"
        );
        Ok(())
    }

    // ===== OAuth PKCE State Operations =====

    pub async fn store_pkce_state(
        &self,
        state: &str,
        code_verifier: &str,
        nonce: &str,
        pkce_challenge: &str,
        redirect_uri: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<(), CrabCakesError> {
        let now = chrono::Utc::now();
        let pkce_state = oauth_pkce_state::ActiveModel {
            state: Set(state.to_string()),
            code_verifier: Set(code_verifier.to_string()),
            nonce: Set(nonce.to_string()),
            pkce_challenge: Set(pkce_challenge.to_string()),
            redirect_uri: Set(redirect_uri.to_string()),
            expires_at: Set(expires_at),
            created_at: Set(now),
        };
        pkce_state.insert(&*self.db).await?;
        debug!(state = %state, "PKCE state stored successfully");
        Ok(())
    }

    pub async fn get_pkce_state(
        &self,
        state: &str,
    ) -> Result<Option<oauth_pkce_state::Model>, CrabCakesError> {
        let pkce_state = oauth_pkce_state::Entity::find_by_id(state)
            .one(&*self.db)
            .await?;
        Ok(pkce_state)
    }

    pub async fn delete_pkce_state(&self, state: &str) -> Result<(), CrabCakesError> {
        let result = oauth_pkce_state::Entity::delete_by_id(state)
            .exec(&*self.db)
            .await?;
        debug!(
            state = %state,
            rows_deleted = result.rows_affected,
            "PKCE state deleted"
        );
        Ok(())
    }

    pub async fn cleanup_expired_pkce_states(&self) -> Result<u64, CrabCakesError> {
        let now = chrono::Utc::now();
        let result = oauth_pkce_state::Entity::delete_many()
            .filter(oauth_pkce_state::Column::ExpiresAt.lt(now))
            .exec(&*self.db)
            .await?;
        debug!(
            rows_deleted = result.rows_affected,
            "Expired PKCE states cleaned up"
        );
        Ok(result.rows_affected)
    }

    // ===== Temporary Credentials Operations =====

    pub async fn store_temporary_credentials(
        &self,
        access_key_id: &str,
        secret_access_key: &str,
        session_id: &str,
        user_email: &str,
        user_id: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<(), CrabCakesError> {
        let now = chrono::Utc::now();
        let creds = temporary_credentials::ActiveModel {
            access_key_id: Set(access_key_id.to_string()),
            secret_access_key: Set(secret_access_key.to_string()),
            session_id: Set(session_id.to_string()),
            user_email: Set(user_email.to_string()),
            user_id: Set(user_id.to_string()),
            expires_at: Set(expires_at),
            created_at: Set(now),
        };
        creds.insert(&*self.db).await?;
        debug!(access_key_id = %access_key_id, "Temporary credentials stored successfully");
        Ok(())
    }

    pub async fn get_temporary_credentials(
        &self,
        access_key_id: &str,
    ) -> Result<Option<temporary_credentials::Model>, CrabCakesError> {
        let creds = temporary_credentials::Entity::find_by_id(access_key_id)
            .one(&*self.db)
            .await?;
        Ok(creds)
    }

    pub async fn get_credentials_by_session(
        &self,
        session_id: &str,
    ) -> Result<Vec<temporary_credentials::Model>, CrabCakesError> {
        let creds = temporary_credentials::Entity::find()
            .filter(temporary_credentials::Column::SessionId.eq(session_id))
            .filter(temporary_credentials::Column::ExpiresAt.gt(Utc::now()))
            .all(&*self.db)
            .await?;
        Ok(creds)
    }

    /// Get valid credentials for a session, or create new ones if none exist or are expired
    /// Returns (credentials, was_created) where was_created is true if new credentials were generated
    pub async fn get_or_create_credentials_for_session(
        &self,
        session_id: &str,
        user_email: &str,
        user_id: &str,
        credential_generator: impl Fn() -> (String, String),
    ) -> Result<(temporary_credentials::Model, bool), CrabCakesError> {
        let now = chrono::Utc::now();

        // Get all credentials for this session
        let session_creds = self.get_credentials_by_session(session_id).await?;

        // Find valid (non-expired) credentials
        let valid_creds: Vec<_> = session_creds
            .iter()
            .filter(|c| c.expires_at > now)
            .collect();

        // Delete any expired credentials for this session
        for cred in session_creds.iter().filter(|c| c.expires_at <= now) {
            debug!(
                access_key_id = %cred.access_key_id,
                session_id = %session_id,
                "Deleting expired credential for session"
            );
            self.delete_temporary_credentials(&cred.access_key_id)
                .await?;
        }

        // If we have a valid credential, return it
        if let Some(cred) = valid_creds.first() {
            debug!(
                access_key_id = %cred.access_key_id,
                session_id = %session_id,
                "Found valid existing credential for session"
            );
            return Ok(((*cred).clone(), false));
        }

        // No valid credentials - create new ones
        let (access_key_id, secret_access_key) = credential_generator();

        // Set credentials to expire in 1 hour
        let expires_at = now + *MAX_TEMP_CREDS_DURATION;

        // Store in database
        self.store_temporary_credentials(
            &access_key_id,
            &secret_access_key,
            session_id,
            user_email,
            user_id,
            expires_at,
        )
        .await?;

        debug!(
            access_key_id = %access_key_id,
            session_id = %session_id,
            "Created new temporary credentials for session"
        );

        // Retrieve and return the newly created credentials
        let creds = self
            .get_temporary_credentials(&access_key_id)
            .await?
            .ok_or_else(|| {
                CrabCakesError::other(&"Failed to retrieve newly created credentials".to_string())
            })?;

        Ok((creds, true))
    }

    pub async fn get_all_temporary_credentials(
        &self,
        order_by: Option<temporary_credentials::Column>,
        direction: Option<Order>,
    ) -> Result<Vec<temporary_credentials::Model>, CrabCakesError> {
        let creds = temporary_credentials::Entity::find()
            .filter(temporary_credentials::Column::ExpiresAt.gt(chrono::Utc::now()))
            .order_by(
                order_by.unwrap_or(temporary_credentials::Column::CreatedAt),
                direction.unwrap_or(Order::Desc),
            )
            .all(&*self.db)
            .await?;
        Ok(creds)
    }

    pub async fn delete_temporary_credentials(
        &self,
        access_key_id: &str,
    ) -> Result<(), CrabCakesError> {
        let result = temporary_credentials::Entity::delete_by_id(access_key_id)
            .exec(&*self.db)
            .await?;
        debug!(
            access_key_id = %access_key_id,
            rows_deleted = result.rows_affected,
            "Temporary credentials deleted"
        );
        Ok(())
    }

    pub async fn delete_credentials_by_session(
        &self,
        session_id: &str,
    ) -> Result<(), CrabCakesError> {
        let result = temporary_credentials::Entity::delete_many()
            .filter(temporary_credentials::Column::SessionId.eq(session_id))
            .exec(&*self.db)
            .await.inspect_err(|err| error!(error=%err, session_id=%session_id, "Failed to delete temporary creds from database!"))?;
        debug!(
            session_id = %session_id,
            rows_deleted = result.rows_affected,
            "Session credentials deleted"
        );
        Ok(())
    }

    pub async fn cleanup_expired_credentials(&self) -> Result<u64, CrabCakesError> {
        let now = chrono::Utc::now();
        let result = temporary_credentials::Entity::delete_many()
            .filter(temporary_credentials::Column::ExpiresAt.lt(now))
            .exec(&*self.db)
            .await?;
        debug!(
            rows_deleted = result.rows_affected,
            "Expired credentials cleaned up"
        );
        Ok(result.rows_affected)
    }

    // ===== Future: Object Metadata Operations =====
    // pub async fn put_object_metadata(...) { ... }
    // pub async fn get_object_metadata(...) { ... }

    // ===== Future: ACL Operations =====
    // pub async fn put_acl(...) { ... }
    // pub async fn get_acl(...) { ... }
}
