//! This cleans up data for files which don't exist

use futures::TryStreamExt;
use std::sync::Arc;
use tracing::{debug, error, info};

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

use crate::{db::entities::object_tags, error::CrabCakesError, filesystem::FilesystemService};

pub(crate) struct TagCleaner {
    db: Arc<DatabaseConnection>,

    fs: Arc<FilesystemService>,

    // Optional timer interval in seconds for periodic cleanup
    // If None, cleanup is run once and returned
    timer: Option<u32>,
}

impl TagCleaner {
    pub(crate) fn new(
        db: Arc<DatabaseConnection>,
        fs: Arc<FilesystemService>,
        timer: Option<u32>,
    ) -> Self {
        Self { db, fs, timer }
    }

    pub(crate) async fn run(&self) -> Result<Option<usize>, CrabCakesError> {
        debug!("Starting tag cleanup run loop...");
        loop {
            let deleted = self
                .cleanup()
                .await
                .inspect_err(|err| error!(error = %err, "Orphaned tag cleanup failed"))?;
            info!(deleted = %deleted, "Orphaned tag cleanup complete");
            if let Some(interval) = self.timer {
                // If timer is set, sleep and continue
                debug!(interval = %interval, "Sleeping before next tag cleanup");
                tokio::time::sleep(std::time::Duration::from_secs(interval as u64)).await;
            } else {
                // If no timer, return the count and exit
                return Ok(Some(deleted));
            }
        }
    }

    async fn cleanup(&self) -> Result<usize, CrabCakesError> {
        let db = self.db.clone();

        let mut deleted_count = 0;
        let mut delete_list = Vec::new();

        // put it in a block to release the stream borrow on db once it's done
        {
            let mut stream = object_tags::Entity::find().stream(&*db).await?;
            while let Some(tag) = stream.try_next().await? {
                // Check if the file exists in storage
                // If not, delete the tag
                // Note: Actual storage check logic is not implemented here

                let tag: object_tags::Model = tag;
                let path = self.fs.resolve_path(&format!("{}/{}", tag.bucket, tag.key));
                if !path.exists() {
                    info!(bucket = %tag.bucket, key = %tag.key, "Orphaned tag found, scheduling for deletion");
                    delete_list.push(tag.id);
                }
            }
        }
        // Perform batch deletion
        if !delete_list.is_empty() {
            deleted_count = delete_list.len();
            object_tags::Entity::delete_many()
                .filter(object_tags::Column::Id.is_in(delete_list))
                .exec(&*db)
                .await?;
        }
        Ok(deleted_count)
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::ActiveValue::{NotSet, Set};

    use super::*;
    use crate::{
        constants::MAX_TEMP_CREDS_DURATION, db::initialize_in_memory_database,
        logging::setup_test_logging, tests::setup_test_files,
    };

    #[tokio::test]
    async fn test_cleanup_no_orphans() {
        setup_test_logging();
        let db = initialize_in_memory_database().await;
        let temp_dir = setup_test_files().await;
        let fs = Arc::new(FilesystemService::new(temp_dir.path().to_path_buf())); // Use a temp directory for testing

        let cleanup = TagCleaner::new(Arc::new(db), fs, None);
        let deleted = cleanup.run().await.expect("Failed to run cleanup");
        assert_eq!(deleted, Some(0)); // No tags to delete
    }

    #[tokio::test]
    async fn test_cleanup_with_orphans() {
        let db = Arc::new(
            initialize_in_memory_database()
                .await
                .expect("Failed to initialize in-memory database"),
        );

        setup_test_logging();
        // Insert a tag for a non-existent file
        let tag_db = db.clone();
        {
            let new_tag = object_tags::ActiveModel {
                id: NotSet,
                bucket: Set("test-bucket".to_string()),
                key: Set("nonexistent.txt".to_string()),
                tag_key: Set("example".to_string()),
                tag_value: Set("value".to_string()),
                created_at: Set(chrono::Utc::now() - *MAX_TEMP_CREDS_DURATION),
            };
            object_tags::Entity::insert(new_tag)
                .exec(&*tag_db)
                .await
                .expect("Failed to insert test tag");
        }

        let temp_dir = setup_test_files().await;
        let fs = Arc::new(FilesystemService::new(temp_dir.path().to_path_buf())); // Use a temp directory for testing

        let cleanup = TagCleaner::new(db.clone(), fs, None);
        let deleted = cleanup.run().await.expect("Failed to run cleanup");
        assert_eq!(deleted, Some(1)); // One orphaned tag should be deleted
    }
}
