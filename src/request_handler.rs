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
    #[allow(dead_code)]
    pub(crate) db: Arc<DBService>,
    #[allow(dead_code)]
    pub(crate) credentials_store: Arc<CredentialStore>,
    pub(crate) policy_store: Arc<PolicyStore>,
    #[allow(dead_code)]
    pub(crate) filesystem: Arc<FilesystemService>,
}

impl RequestHandler {
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

        let credentials_store = CredentialStore::new_test().await;
        let policy_dir = tempfile::tempdir().expect("Failed to create temp dir");
        copy_dir_all("test_config/policies", policy_dir.path())
            .expect("Failed to copy test policies");
        let policy_store = Arc::new(
            PolicyStore::new(&policy_dir.path().to_path_buf()).expect("Failed to load policies"),
        );
        let filesystem = Arc::new(FilesystemService::new(tempdir.path().join("data/")));

        Self {
            db,
            credentials_store,
            policy_store,
            filesystem,
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
}
