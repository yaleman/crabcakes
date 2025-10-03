//! Database migrations using SeaORM migration framework

use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250103_000001_create_object_tags::Migration),
            // Future migrations added here
        ]
    }
}

pub mod m20250103_000001_create_object_tags;
