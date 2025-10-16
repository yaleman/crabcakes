//! Database layer for metadata storage (tags, object attributes, ACLs, etc.)
//!
//! Uses SQLite with SeaORM for schema management and migrations.

pub mod cleanup;
pub mod entities;
pub mod migration;
mod service;

pub use service::DBService;

use sea_orm::{Database, DatabaseConnection, DbErr};
use sea_orm_migration::prelude::*;
use std::path::Path;
use tokio::fs::create_dir_all;
use tracing::{debug, info};

use migration::Migrator;

/// Initialize database connection and run migrations
pub async fn initialize_database(config_dir: &Path) -> Result<DatabaseConnection, DbErr> {
    let db_path = config_dir.join("crabcakes.sqlite3");

    // Create config directory if it doesn't exist
    if !config_dir.exists() {
        create_dir_all(config_dir)
            .await
            .map_err(|e| DbErr::Custom(format!("Failed to create config dir: {}", e)))?;
    }

    // Build connection string
    let connection_string = format!("sqlite://{}?mode=rwc", db_path.display());

    debug!("Connecting to database at {}", db_path.display());

    let db = Database::connect(&connection_string).await?;

    // Configure SQLite PRAGMAs for optimal performance and incremental vacuum
    configure_sqlite_pragmas(&db).await?;

    // Run migrations
    info!("Running database migrations...");
    Migrator::up(&db, None).await?;
    info!("Database migrations complete");

    Ok(db)
}

/// Configure SQLite PRAGMA settings for performance and maintenance
async fn configure_sqlite_pragmas(db: &DatabaseConnection) -> Result<(), DbErr> {
    use sea_orm::ConnectionTrait;

    // Enable WAL mode for better concurrency
    db.execute_unprepared("PRAGMA journal_mode = WAL").await?;

    // Set cache size to 16MB (negative value = KiB)
    db.execute_unprepared("PRAGMA cache_size = -16000").await?;

    // Use memory for temporary storage
    db.execute_unprepared("PRAGMA temp_store = MEMORY").await?;

    // Set memory-mapped I/O size to 10MB
    db.execute_unprepared("PRAGMA mmap_size = 10485760").await?;

    // Enable incremental vacuum for space reclamation
    db.execute_unprepared("PRAGMA auto_vacuum = INCREMENTAL")
        .await?;

    debug!("SQLite PRAGMA configuration complete");
    Ok(())
}

/// Initialize in-memory database for testing
#[cfg(test)]
pub async fn initialize_in_memory_database() -> Result<DatabaseConnection, DbErr> {
    let db = Database::connect("sqlite::memory:").await?;

    // Configure SQLite PRAGMAs (even for in-memory, for consistency)
    configure_sqlite_pragmas(&db).await?;

    // Run migrations
    Migrator::up(&db, None).await?;

    Ok(db)
}
