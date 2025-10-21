use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(BucketWebsiteConfigs::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(BucketWebsiteConfigs::Bucket)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(BucketWebsiteConfigs::IndexDocumentSuffix)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(BucketWebsiteConfigs::ErrorDocumentKey).string())
                    .col(
                        ColumnDef::new(BucketWebsiteConfigs::CreatedAt)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BucketWebsiteConfigs::UpdatedAt)
                            .date_time()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(BucketWebsiteConfigs::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum BucketWebsiteConfigs {
    Table,
    Bucket,
    IndexDocumentSuffix,
    ErrorDocumentKey,
    CreatedAt,
    UpdatedAt,
}
