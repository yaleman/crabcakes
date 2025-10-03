//! Object tags entity model

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "object_tags")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub bucket: String,
    pub key: String,
    pub tag_key: String,
    pub tag_value: String,
    pub created_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
