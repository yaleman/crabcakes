//! Background cleanup task for expired database records

use std::sync::Arc;
use tokio::time::{Duration, interval};
use tracing::{error, info};

use crate::db::DBService;

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

            // Cleanup expired PKCE states
            match self.db.cleanup_expired_pkce_states().await {
                Ok(count) => {
                    if count > 0 {
                        info!(count = count, "Cleaned up expired PKCE states");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to cleanup expired PKCE states");
                }
            }

            // Cleanup expired temporary credentials
            match self.db.cleanup_expired_credentials().await {
                Ok(count) => {
                    if count > 0 {
                        info!(count = count, "Cleaned up expired temporary credentials");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to cleanup expired temporary credentials");
                }
            }
        }
    }
}
