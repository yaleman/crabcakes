//! Database service providing business logic for all database operations

use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use std::sync::Arc;
use tracing::debug;

use super::entities::object_tags;
use crate::error::CrabCakesError;

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
        let now = chrono::Utc::now().naive_utc();
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

    // ===== Future: Object Metadata Operations =====
    // pub async fn put_object_metadata(...) { ... }
    // pub async fn get_object_metadata(...) { ... }

    // ===== Future: ACL Operations =====
    // pub async fn put_acl(...) { ... }
    // pub async fn get_acl(...) { ... }
}
