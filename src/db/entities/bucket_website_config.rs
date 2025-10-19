//! Bucket website configuration entity model

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "bucket_website_configs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub bucket: String,
    pub index_document_suffix: String,
    pub error_document_key: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
