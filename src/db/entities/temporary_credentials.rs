//! Temporary credentials entity model

use chrono::Utc;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "temporary_credentials")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_id: String,
    pub user_email: String,
    pub user_id: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
