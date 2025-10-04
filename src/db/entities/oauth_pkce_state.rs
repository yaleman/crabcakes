//! OAuth PKCE state entity model

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "oauth_pkce_state")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub state: String,
    pub code_verifier: String,
    pub nonce: String,
    pub pkce_challenge: String,
    pub redirect_uri: String,
    pub expires_at: DateTime,
    pub created_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
