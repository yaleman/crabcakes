use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(OauthPkceState::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OauthPkceState::State)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(OauthPkceState::CodeVerifier)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(OauthPkceState::Nonce).string().not_null())
                    .col(
                        ColumnDef::new(OauthPkceState::PkceChallenge)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OauthPkceState::RedirectUri)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OauthPkceState::ExpiresAt)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OauthPkceState::CreatedAt)
                            .date_time()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on expires_at for cleanup
        manager
            .create_index(
                Index::create()
                    .name("idx_oauth_pkce_state_expires")
                    .table(OauthPkceState::Table)
                    .col(OauthPkceState::ExpiresAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(OauthPkceState::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum OauthPkceState {
    Table,
    State,
    CodeVerifier,
    Nonce,
    PkceChallenge,
    RedirectUri,
    ExpiresAt,
    CreatedAt,
}
