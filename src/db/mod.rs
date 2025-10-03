//! Database layer for metadata storage (tags, object attributes, ACLs, etc.)
//!
//! Uses SQLite with SeaORM for schema management and migrations.

pub mod entities;
pub mod migration;
mod service;

pub use service::DBService;

use sea_orm::{Database, DatabaseConnection, DbErr};
use sea_orm_migration::prelude::*;
use std::path::Path;
use tracing::{debug, info};

use migration::Migrator;

/// Initialize database connection and run migrations
pub async fn initialize_database(config_dir: &Path) -> Result<DatabaseConnection, DbErr> {
    let db_path = config_dir.join("crabcakes.sqlite3");

    // Create config directory if it doesn't exist
    if !config_dir.exists() {
        std::fs::create_dir_all(config_dir)
            .map_err(|e| DbErr::Custom(format!("Failed to create config dir: {}", e)))?;
    }

    // Build connection string
    let connection_string = format!("sqlite://{}?mode=rwc", db_path.display());

    debug!("Connecting to database at {}", db_path.display());
    let db = Database::connect(&connection_string).await?;

    // Run migrations
    info!("Running database migrations...");
    Migrator::up(&db, None).await?;
    info!("Database migrations complete");

    Ok(db)
}

/// Initialize in-memory database for testing
#[cfg(test)]
pub async fn initialize_in_memory_database() -> Result<DatabaseConnection, DbErr> {
    let db = Database::connect("sqlite::memory:").await?;

    // Run migrations
    Migrator::up(&db, None).await?;

    Ok(db)
}
