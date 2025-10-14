//! Internal handler for requests
use std::{str::FromStr, sync::Arc};

use iam_rs::{Arn, EvaluationOptions, IAMRequest, PolicyEvaluator, PrincipalId};
use tracing::debug;

use crate::{
    credentials::CredentialStore,
    db::DBService,
    error::CrabCakesError,
    filesystem::FilesystemService,
    policy::PolicyStore,
    web::serde::{TroubleShooterForm, TroubleShooterResponse},
};

pub(crate) struct RequestHandler {
    pub(crate) db: Arc<DBService>,
    pub(crate) credentials_store: Arc<CredentialStore>,
    pub(crate) policy_store: Arc<PolicyStore>,
    pub(crate) filesystem: Arc<FilesystemService>,
    // Keep temp directories alive for testing
    #[cfg(test)]
    _test_dirs: Option<(tempfile::TempDir, tempfile::TempDir, tempfile::TempDir)>,
}

impl RequestHandler {
    /// Constructor for production use
    pub fn new(
        db: Arc<DBService>,
        credentials_store: Arc<CredentialStore>,
        policy_store: Arc<PolicyStore>,
        filesystem: Arc<FilesystemService>,
    ) -> Self {
        Self {
            db,
            credentials_store,
            policy_store,
            filesystem,
            #[cfg(test)]
            _test_dirs: None,
        }
    }

    #[cfg(test)]
    pub async fn new_test() -> Self {
        use crate::{
            db::initialize_in_memory_database,
            tests::{copy_dir_all, setup_test_files},
        };

        let tempdir = setup_test_files();

        let db = Arc::new(
            initialize_in_memory_database()
                .await
                .expect("Failed to init in-memory DB"),
        );
        let db = Arc::new(DBService::new(db));

        // Create temp credential directory for testing
        let cred_dir = tempfile::tempdir().expect("Failed to create temp credentials dir");
        let cred_path = cred_dir.path().to_path_buf();
        let credentials_store = Arc::new(
            CredentialStore::new(&cred_path)
                .await
                .expect("Failed to create CredentialStore"),
        );

        // Create temp policy directory and copy test policies
        let policy_dir = tempfile::tempdir().expect("Failed to create temp policy dir");
        std::fs::create_dir_all(policy_dir.path()).expect("Failed to create policy dir");
        copy_dir_all("test_config/policies", policy_dir.path())
            .expect("Failed to copy test policies");
        let policy_store = Arc::new(
            PolicyStore::new(&policy_dir.path().to_path_buf()).expect("Failed to load policies"),
        );

        // Ensure data directory exists for filesystem operations
        let data_dir = tempdir.path().join("data/");
        std::fs::create_dir_all(&data_dir).expect("Failed to create data dir");
        let filesystem = Arc::new(FilesystemService::new(data_dir));

        Self {
            db,
            credentials_store,
            policy_store,
            filesystem,
            #[cfg(test)]
            _test_dirs: Some((tempdir, cred_dir, policy_dir)),
        }
    }

    /// Inner caller for the troubleshooter logic, separated for testing
    pub(crate) async fn api_troubleshooter(
        &self,
        form: TroubleShooterForm,
    ) -> Result<TroubleShooterResponse, CrabCakesError> {
        let mut arnstr = form.bucket.to_string();
        if arnstr.is_empty() {
            arnstr.push('*');
        }

        if !form.key.is_empty() {
            arnstr.push_str(&format!("/{}", form.key));
        };

        let iam_request = IAMRequest::new(
            iam_rs::Principal::Aws(PrincipalId::String(format!(
                "arn:aws:iam:::user/{}",
                form.user
            ))),
            form.action.clone(),
            Arn::from_str(&format!("arn:aws:s3:::{arnstr}"))?,
        );

        // Apply the same transformation that PolicyStore uses
        let request_json = crate::policy::fix_mock_id(&serde_json::to_string(&iam_request)?);
        let iam_request: IAMRequest = serde_json::from_str(&request_json)?;

        // look for a policy that matches the bucket and key
        let policies = self.policy_store.policies.read().await;
        let filtered_policies = policies
            .iter()
            .filter_map(|(name, policy)| match &form.policy.is_empty() {
                false => {
                    if name == &form.policy {
                        Some(policy.clone())
                    } else {
                        None
                    }
                }
                true => Some(policy.clone()),
            })
            .collect();

        let policyevaluator =
            PolicyEvaluator::with_policies(filtered_policies).with_options(EvaluationOptions {
                stop_on_explicit_deny: false,
                collect_match_details: true,
                max_statements: usize::MAX,
                ignore_resource_constraints: false,
            });
        let evaluation_result = policyevaluator.evaluate(&iam_request)?;

        let response = TroubleShooterResponse {
            decision: evaluation_result,
        };
        debug!("Troubleshooter response: {:?}", response);
        Ok(response)
    }

    pub(crate) async fn api_delete_bucket(
        &self,
        bucket: &str,
        force: bool,
    ) -> Result<(), CrabCakesError> {
        if force {
            // Delete all objects in the bucket first
            let (entries, _) = self
                .filesystem
                .list_directory(Some(&format!("{bucket}/")), 10000, None)
                .map_err(CrabCakesError::from)?;

            // Delete each object
            for entry in entries {
                self.filesystem
                    .delete_file(&entry.key)
                    .await
                    .map_err(CrabCakesError::from)?;
            }
        }

        // Delete the bucket (will fail if not empty and force=false)
        self.filesystem
            .delete_bucket(bucket)
            .await
            .map_err(CrabCakesError::from)
    }

    pub(crate) async fn api_create_bucket(&self, bucket_name: &str) -> Result<(), CrabCakesError> {
        // FilesystemService handles all validation (name validation, reserved names, etc.)
        self.filesystem
            .create_bucket(bucket_name)
            .await
            .map_err(CrabCakesError::from)
    }

    pub(crate) async fn api_list_policies(
        &self,
    ) -> Result<Vec<crate::web::serde::ApiPolicyInfo>, CrabCakesError> {
        let policy_names = self.policy_store.get_policy_names().await;
        let mut policies = Vec::new();

        for name in policy_names {
            if let Some(policy) = self.policy_store.get_policy(&name).await {
                policies.push(crate::web::serde::ApiPolicyInfo {
                    name,
                    policy: serde_json::to_value(&policy)?,
                });
            }
        }

        // Sort by name for consistent ordering
        policies.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(policies)
    }

    pub(crate) async fn api_create_policy(
        &self,
        name: &str,
        policy: iam_rs::IAMPolicy,
    ) -> Result<(), CrabCakesError> {
        // PolicyStore handles validation and file writing
        self.policy_store.add_policy(name, policy).await
    }

    pub(crate) async fn api_update_policy(
        &self,
        name: String,
        policy: iam_rs::IAMPolicy,
    ) -> Result<(), CrabCakesError> {
        // PolicyStore handles validation and file writing
        self.policy_store.update_policy(name, policy).await
    }

    pub(crate) async fn api_delete_policy(&self, name: &str) -> Result<(), CrabCakesError> {
        // PolicyStore handles file deletion
        self.policy_store.delete_policy(name).await
    }

    pub(crate) async fn api_list_credentials(
        &self,
    ) -> Result<Vec<crate::web::serde::CredentialInfo>, CrabCakesError> {
        let mut access_key_ids = self.credentials_store.get_access_key_ids().await;
        access_key_ids.sort();

        Ok(access_key_ids
            .into_iter()
            .map(|access_key_id| crate::web::serde::CredentialInfo { access_key_id })
            .collect())
    }

    pub(crate) async fn api_create_credential(
        &self,
        access_key_id: String,
        secret_access_key: String,
    ) -> Result<(), CrabCakesError> {
        // CredentialStore handles validation and file writing
        self.credentials_store
            .write_credential(access_key_id, secret_access_key)
            .await
    }

    pub(crate) async fn api_update_credential(
        &self,
        access_key_id: String,
        secret_access_key: String,
    ) -> Result<(), CrabCakesError> {
        // CredentialStore handles validation and file writing
        self.credentials_store
            .update_credential(access_key_id, secret_access_key)
            .await
    }

    pub(crate) async fn api_delete_credential(
        &self,
        access_key_id: &str,
    ) -> Result<(), CrabCakesError> {
        // CredentialStore handles file deletion
        self.credentials_store
            .delete_credential(access_key_id)
            .await
    }

    pub(crate) async fn api_delete_temp_credential(
        &self,
        access_key_id: &str,
    ) -> Result<(), CrabCakesError> {
        // Delete from database (idempotent)
        self.db.delete_temporary_credentials(access_key_id).await
    }

    pub(crate) async fn api_database_vacuum_status(
        &self,
    ) -> Result<crate::web::serde::VacuumStats, CrabCakesError> {
        let stats = self.db.get_vacuum_stats().await?;

        // SQLite page size is typically 4096 bytes, but let's use a default
        // The actual page size isn't exposed by get_vacuum_stats, and we don't need it
        // for the percentage calculation which is already done
        let page_size = 4096i64; // Default SQLite page size

        Ok(crate::web::serde::VacuumStats {
            page_count: stats.page_count,
            page_size,
            freelist_count: stats.freelist_count,
            total_size_bytes: stats.page_count * page_size,
            freelist_size_bytes: stats.freelist_count * page_size,
        })
    }

    pub(crate) async fn api_database_vacuum(
        &self,
        confirm: bool,
    ) -> Result<crate::web::serde::VacuumResult, CrabCakesError> {
        if !confirm {
            return Err(CrabCakesError::other(
                &"Must confirm vacuum operation with confirm=true",
            ));
        }

        let pages_freed = self.db.vacuum_database().await?;

        Ok(crate::web::serde::VacuumResult {
            success: true,
            pages_freed,
        })
    }
}
