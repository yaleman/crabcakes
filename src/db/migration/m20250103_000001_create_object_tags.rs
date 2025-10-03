use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ObjectTags::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ObjectTags::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ObjectTags::Bucket).string().not_null())
                    .col(ColumnDef::new(ObjectTags::Key).string().not_null())
                    .col(ColumnDef::new(ObjectTags::TagKey).string().not_null())
                    .col(ColumnDef::new(ObjectTags::TagValue).string().not_null())
                    .col(ColumnDef::new(ObjectTags::CreatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        // Create unique constraint on (bucket, key, tag_key)
        manager
            .create_index(
                Index::create()
                    .name("idx_object_tags_unique")
                    .table(ObjectTags::Table)
                    .col(ObjectTags::Bucket)
                    .col(ObjectTags::Key)
                    .col(ObjectTags::TagKey)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Create index on (bucket, key) for fast lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_object_tags_lookup")
                    .table(ObjectTags::Table)
                    .col(ObjectTags::Bucket)
                    .col(ObjectTags::Key)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ObjectTags::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum ObjectTags {
    Table,
    Id,
    Bucket,
    Key,
    TagKey,
    TagValue,
    CreatedAt,
}
