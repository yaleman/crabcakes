//! Background cleanup task for expired database records

use std::sync::Arc;
use tokio::time::{Duration, interval};
use tracing::{error, info};

use crate::db::DBService;
use crate::error::CrabCakesError;

/// Background cleanup task that periodically removes expired PKCE states and temporary credentials
pub struct CleanupTask {
    db: Arc<DBService>,
    interval_secs: u64,
}

impl CleanupTask {
    /// Create a new cleanup task
    pub fn new(db: Arc<DBService>, interval_secs: u64) -> Self {
        Self { db, interval_secs }
    }

    /// Run the cleanup task in an infinite loop
    pub async fn run(self) {
        let mut timer = interval(Duration::from_secs(self.interval_secs));

        loop {
            timer.tick().await;

            if let Err(e) = self.run_cleanup().await {
                error!(error = %e, "Cleanup cycle failed");
            }
        }
    }

    /// Run a single cleanup cycle (public for testing)
    pub async fn run_cleanup(&self) -> Result<(u64, u64), CrabCakesError> {
        // Cleanup expired PKCE states
        let pkce_count = match self.db.cleanup_expired_pkce_states().await {
            Ok(count) => {
                if count > 0 {
                    info!(count = count, "Cleaned up expired PKCE states");
                }
                count
            }
            Err(e) => {
                error!(error = %e, "Failed to cleanup expired PKCE states");
                return Err(e);
            }
        };

        // Cleanup expired temporary credentials
        let creds_count = match self.db.cleanup_expired_credentials().await {
            Ok(count) => {
                if count > 0 {
                    info!(count = count, "Cleaned up expired temporary credentials");
                }
                count
            }
            Err(e) => {
                error!(error = %e, "Failed to cleanup expired temporary credentials");
                return Err(e);
            }
        };

        Ok((pkce_count, creds_count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::initialize_in_memory_database;

    #[tokio::test]
    async fn test_cleanup_task_no_expired_data() {
        crate::setup_test_logging();

        let db = initialize_in_memory_database().await.unwrap();
        let db_service = Arc::new(DBService::new(Arc::new(db)));

        let cleanup = CleanupTask::new(db_service, 1);
        let (pkce_count, creds_count) = cleanup.run_cleanup().await.unwrap();

        assert_eq!(pkce_count, 0, "Should not clean up any PKCE states");
        assert_eq!(creds_count, 0, "Should not clean up any credentials");
    }

    #[tokio::test]
    async fn test_cleanup_task_cleans_expired_pkce() {
        crate::setup_test_logging();

        let db = initialize_in_memory_database().await.unwrap();
        let db_service = Arc::new(DBService::new(Arc::new(db)));

        // Store expired PKCE state (expired 1 hour ago)
        let expired_at = chrono::Utc::now().naive_utc() - chrono::Duration::try_hours(1).unwrap();
        db_service
            .store_pkce_state(
                "expired_state",
                "verifier123",
                "nonce123",
                "challenge123",
                "http://localhost/callback",
                expired_at,
            )
            .await
            .unwrap();

        // Store valid PKCE state (expires in 10 minutes)
        let valid_expires =
            chrono::Utc::now().naive_utc() + chrono::Duration::try_minutes(10).unwrap();
        db_service
            .store_pkce_state(
                "valid_state",
                "verifier456",
                "nonce456",
                "challenge456",
                "http://localhost/callback",
                valid_expires,
            )
            .await
            .unwrap();

        // Run cleanup
        let cleanup = CleanupTask::new(db_service.clone(), 1);
        let (pkce_count, _) = cleanup.run_cleanup().await.unwrap();

        assert_eq!(pkce_count, 1, "Should clean up 1 expired PKCE state");

        // Verify expired state was deleted
        let expired_state = db_service.get_pkce_state("expired_state").await.unwrap();
        assert!(expired_state.is_none(), "Expired state should be deleted");

        // Verify valid state still exists
        let valid_state = db_service.get_pkce_state("valid_state").await.unwrap();
        assert!(valid_state.is_some(), "Valid state should still exist");
    }

    #[tokio::test]
    async fn test_cleanup_task_cleans_expired_credentials() {
        crate::setup_test_logging();

        let db = initialize_in_memory_database().await.unwrap();
        let db_service = Arc::new(DBService::new(Arc::new(db)));

        // Store expired credentials (expired 1 hour ago)
        let expired_at = chrono::Utc::now().naive_utc() - chrono::Duration::try_hours(1).unwrap();
        db_service
            .store_temporary_credentials(
                "EXPIRED_KEY_123",
                "expired_secret",
                "session1",
                "user@example.com",
                "user123",
                expired_at,
            )
            .await
            .unwrap();

        // Store valid credentials (expires in 10 minutes)
        let valid_expires =
            chrono::Utc::now().naive_utc() + chrono::Duration::try_minutes(10).unwrap();
        db_service
            .store_temporary_credentials(
                "VALID_KEY_456",
                "valid_secret",
                "session2",
                "user@example.com",
                "user456",
                valid_expires,
            )
            .await
            .unwrap();

        // Run cleanup
        let cleanup = CleanupTask::new(db_service.clone(), 1);
        let (_, creds_count) = cleanup.run_cleanup().await.unwrap();

        assert_eq!(creds_count, 1, "Should clean up 1 expired credential");

        // Verify expired credentials were deleted
        let expired_creds = db_service
            .get_temporary_credentials("EXPIRED_KEY_123")
            .await
            .unwrap();
        assert!(
            expired_creds.is_none(),
            "Expired credentials should be deleted"
        );

        // Verify valid credentials still exist
        let valid_creds = db_service
            .get_temporary_credentials("VALID_KEY_456")
            .await
            .unwrap();
        assert!(
            valid_creds.is_some(),
            "Valid credentials should still exist"
        );
    }

    #[tokio::test]
    async fn test_cleanup_task_cleans_both_types() {
        crate::setup_test_logging();

        let db = initialize_in_memory_database().await.unwrap();
        let db_service = Arc::new(DBService::new(Arc::new(db)));

        let expired_at = chrono::Utc::now().naive_utc() - chrono::Duration::try_hours(1).unwrap();

        // Store expired PKCE state
        db_service
            .store_pkce_state(
                "expired_state",
                "verifier",
                "nonce",
                "challenge",
                "http://localhost/callback",
                expired_at,
            )
            .await
            .unwrap();

        // Store expired credentials
        db_service
            .store_temporary_credentials(
                "EXPIRED_KEY",
                "secret",
                "session1",
                "user@example.com",
                "user1",
                expired_at,
            )
            .await
            .unwrap();

        // Run cleanup
        let cleanup = CleanupTask::new(db_service, 1);
        let (pkce_count, creds_count) = cleanup.run_cleanup().await.unwrap();

        assert_eq!(pkce_count, 1, "Should clean up 1 PKCE state");
        assert_eq!(creds_count, 1, "Should clean up 1 credential");
    }
}
