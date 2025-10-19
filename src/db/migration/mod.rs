//! Database migrations using SeaORM migration framework

use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250103_000001_create_object_tags::Migration),
            Box::new(m20250104_000001_create_oauth_pkce_state::Migration),
            Box::new(m20250104_000002_create_temporary_credentials::Migration),
            Box::new(m20250119_000001_create_bucket_website_configs::Migration),
        ]
    }
}

pub mod m20250103_000001_create_object_tags;
pub mod m20250104_000001_create_oauth_pkce_state;
pub mod m20250104_000002_create_temporary_credentials;
pub mod m20250119_000001_create_bucket_website_configs;
