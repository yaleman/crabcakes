//! Object tags entity model

use sea_orm::entity::prelude::*;

use crate::error::CrabCakesError;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "object_tags")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub bucket: String,
    pub key: String,
    pub tag_key: String,
    pub tag_value: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

pub(crate) async fn delete_bucket(
    db: &DatabaseConnection,
    bucket: &str,
) -> Result<usize, CrabCakesError> {
    use sea_orm::QueryFilter;

    Entity::delete_many()
        .filter(Column::Bucket.eq(bucket))
        .exec(db)
        .await
        .map_err(CrabCakesError::from)
        .map(|res| res.rows_affected as usize)
}
