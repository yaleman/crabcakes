use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(TemporaryCredentials::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TemporaryCredentials::AccessKeyId)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TemporaryCredentials::SecretAccessKey)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TemporaryCredentials::SessionId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TemporaryCredentials::UserEmail)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TemporaryCredentials::UserId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TemporaryCredentials::ExpiresAt)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TemporaryCredentials::CreatedAt)
                            .date_time()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on session_id for lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_temporary_credentials_session")
                    .table(TemporaryCredentials::Table)
                    .col(TemporaryCredentials::SessionId)
                    .to_owned(),
            )
            .await?;

        // Create index on expires_at for cleanup
        manager
            .create_index(
                Index::create()
                    .name("idx_temporary_credentials_expires")
                    .table(TemporaryCredentials::Table)
                    .col(TemporaryCredentials::ExpiresAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(TemporaryCredentials::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum TemporaryCredentials {
    Table,
    AccessKeyId,
    SecretAccessKey,
    SessionId,
    UserEmail,
    UserId,
    ExpiresAt,
    CreatedAt,
}
