//! IAM policy storage and evaluation.
//!
//! Loads JSON IAM policies and evaluates requests against them with caching support.
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::{collections::HashMap, sync::Arc};

use chrono::{DateTime, Utc};
use iam_rs::{
    Decision, EvaluationResult, IAMAction, IAMEffect, IAMPolicy, IAMRequest, IAMResource,
    PolicyEvaluator, Principal,
};
use sha2::{Digest, Sha256};
#[cfg(test)]
use tempfile::TempDir;
use tokio::fs::{self, read_dir};
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::constants::MOCK_ACCOUNT_ID;
use crate::error::CrabCakesError;

fn hash_request(request: &IAMRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{:?}", request.principal));
    hasher.update(&request.action);
    hasher.update(request.resource.to_string());
    hasher.update(format!(
        "{:?}",
        serde_json::to_string(&request.context).unwrap_or(format!("{:?}", request.context))
    ));
    format!("{:x}", hasher.finalize())
}

pub(crate) fn fix_mock_id(input: &impl ToString) -> String {
    input.to_string().replace(
        "arn:aws:iam:::",
        &format!("arn:aws:iam::{MOCK_ACCOUNT_ID}:"),
    )
}

struct CachedResult {
    evaluation_result: EvaluationResult,
    timestamp: DateTime<Utc>,
}

impl CachedResult {
    pub fn new(evaluation_result: EvaluationResult, timestamp: DateTime<Utc>) -> Self {
        Self {
            evaluation_result,
            timestamp,
        }
    }
    pub(crate) fn expired(&self, expiry_secs: u32) -> bool {
        let age = Utc::now().signed_duration_since(self.timestamp);
        age.num_seconds() >= i64::from(expiry_secs)
    }
}

pub struct PolicyStore {
    pub policies: Arc<RwLock<HashMap<String, IAMPolicy>>>,
    result_cache: Arc<RwLock<HashMap<String, CachedResult>>>,
    policy_dir: PathBuf,
    expiry_secs: Arc<RwLock<u32>>,
}

static NAME_VALIDATOR: LazyLock<regex::Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    regex::Regex::new(r"^[a-zA-Z0-9]{1}[a-zA-Z0-9-_]*[a-zA-Z0-9]{1}$")
        .expect("Failed to compile policy name regex")
});

impl PolicyStore {
    /// Create a new PolicyStore by loading policies from the given directory
    pub async fn new(policy_dir: &PathBuf) -> Result<Self, CrabCakesError> {
        if !policy_dir.exists() {
            warn!(policy_dir = ?policy_dir, "Policy directory does not exist, creating it...");
            fs::create_dir_all(policy_dir).await.inspect_err(|err| {
                error!(
                    policy_dir = ?policy_dir,
                    error = %err,
                    "Failed to create policy directory"
                )
            })?;
        } else {
            info!(policy_dir = ?policy_dir, "Loading IAM policies");
        }

        if !policy_dir.is_dir() {
            error!(policy_dir = ?policy_dir, "Policy path is not a directory");
            return Err(CrabCakesError::other(&"Policy path is not a directory"));
        }

        // Read all JSON files from the policy directory

        let res = Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            result_cache: Arc::new(RwLock::new(Default::default())),
            policy_dir: policy_dir.clone(),
            expiry_secs: Arc::new(RwLock::new(300)), // cache expiry in seconds
        };
        let loaded_count = res.load_policies().await?;
        info!(count = loaded_count, "Loaded IAM policies");
        Ok(res)
    }

    #[cfg(test)]
    /// Make sure you don't accidentally drop the tempdir, so do something like this:
    /// ```
    /// use crate::policy::PolicyStore;
    /// let (_tempdir, policy_store) = PolicyStore::test_empty_store();
    /// ```
    pub async fn new_test() -> (TempDir, Self) {
        let tempdir = tempfile::tempdir().expect("failed to create temp dir");

        let path = tempdir.path().to_path_buf();
        (
            tempdir,
            Self::new(&path)
                .await
                .expect("failed to create policystore"),
        )
    }
    pub(crate) async fn load_policies(&self) -> Result<usize, CrabCakesError> {
        let policies = self.policies.clone();
        let mut policy_writer = policies.write().await;

        let mut loaded_policies = HashSet::new();
        let mut reader = read_dir(&self.policy_dir).await?;
        while let Some(entry) = reader.next_entry().await? {
            let path = entry.path();

            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                match Self::load_policy(&path).await {
                    Ok(policy) => {
                        let policy_name = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown")
                            .to_string();
                        debug!(policy_name = %policy_name, path = ?path, "Loaded policy");
                        loaded_policies.insert(policy_name.clone());
                        policy_writer.insert(policy_name, policy);
                    }
                    Err(e) => {
                        error!(path = ?path, error = %e, "Failed to load policy");
                    }
                }
            }
            let known_policies: Vec<String> = policy_writer.keys().cloned().collect();
            for existing_policy in known_policies {
                if !loaded_policies.contains(&existing_policy) {
                    warn!(policy_name = %existing_policy, "Policy file no longer exists, removing from store");
                    policy_writer.remove(&existing_policy);
                }
            }
        }
        Ok(loaded_policies.len())
    }

    /// Load a single policy from a JSON file
    async fn load_policy(path: &PathBuf) -> Result<IAMPolicy, CrabCakesError> {
        let contents = fs::read_to_string(path).await.inspect_err(
            |err| error!(policy_path = path.display().to_string(), error = ?err, "Failed to read policy file"),
        )?;
        debug!(contents = contents.replace("\\n", ""), "Loaded policy JSON");
        // Apply mock ID transformation to match request transformation
        let transformed_contents = fix_mock_id(&contents);
        let policy: IAMPolicy = serde_json::from_str(&transformed_contents)?;
        Ok(policy)
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn get_cached_result(&self, request: &IAMRequest) -> Option<EvaluationResult> {
        let hashed_request: String = hash_request(request);
        let mut cache = self.result_cache.write().await;
        if let Some(cached_result) = cache.get(&hashed_request) {
            if !cached_result.expired(*self.expiry_secs.read().await) {
                debug!("Found cached decision");
                return Some(cached_result.evaluation_result.clone());
            } else {
                debug!("Cache entry expired for request");
                cache.remove(&hashed_request);
            }
        }
        None
    }
    pub async fn evaluate_request(&self, request: &IAMRequest) -> Result<Decision, CrabCakesError> {
        self.debug_evaluate_request(request)
            .await
            .map(|(_, decision)| decision)
    }

    /// Evaluate a request against all loaded policies
    /// Returns true if the request is allowed, false if denied or no policy matches
    pub async fn debug_evaluate_request(
        &self,
        request: &IAMRequest,
    ) -> Result<(Option<EvaluationResult>, Decision), CrabCakesError> {
        // serialise the request then replace the account ID with the mock one
        let request_json = fix_mock_id(&serde_json::to_string(request)?);
        let request: IAMRequest = serde_json::from_str(&request_json)?;

        debug!(
            principal = ?request.principal,
            action = %request.action,
            resource = %request.resource,
            "Evaluating request"
        );

        // Handle wildcard/anonymous principals specially, since iam-rs treats them as errors
        // Check if any policy explicitly allows anonymous access
        if matches!(request.principal, Principal::Wildcard) {
            debug!("Handling wildcard/anonymous request");

            // Look for policies that allow wildcard principals
            let policies = self.policies.read().await;
            for policy in policies.values() {
                // Check each statement in the policy
                for statement in &policy.statement {
                    // Check if this statement allows the action and resource
                    // For anonymous access, we look for statements with Principal: "*"
                    // TODO: handle notprincipal, notallow etc etc etc
                    if statement.effect == IAMEffect::Allow {
                        // Check if principal matches (looking for "*")
                        if matches!(&statement.principal, Some(Principal::Wildcard)) {
                            // Check if action matches
                            let action_matches = match &statement.action {
                                Some(IAMAction::Single(action)) => {
                                    action == &request.action || action == "*" || action == "s3:*"
                                }
                                Some(IAMAction::Multiple(actions)) => actions
                                    .iter()
                                    .any(|a| a == &request.action || a == "*" || a == "s3:*"),
                                _ => false,
                            };

                            if action_matches {
                                // Check if resource matches
                                let resource_matches = match &statement.resource {
                                    Some(IAMResource::Single(resource)) => {
                                        if resource == &request.resource.to_string()
                                            || resource == "*"
                                            || resource == "arn:aws:s3:::*"
                                        {
                                            Decision::Allow
                                        } else {
                                            Decision::Deny
                                        }
                                    }
                                    Some(IAMResource::Multiple(resources)) => {
                                        if resources.iter().any(|r| {
                                            r == &request.resource.to_string()
                                                || r == "*"
                                                || r == "arn:aws:s3:::*"
                                        }) {
                                            Decision::Allow
                                        } else {
                                            Decision::Deny
                                        }
                                    }
                                    _ => Decision::Deny,
                                };
                                debug!("Anonymous access allowed by policy");
                                return Ok((None, resource_matches));
                            }
                        }
                    }
                }
            }

            debug!("No policy allows anonymous access for this request");
            return Ok((None, Decision::NotApplicable));
        }

        // check for a result in the cache
        let hashed_request = hash_request(&request);
        let res = {
            let cached_result = self.get_cached_result(&request).await;
            match cached_result {
                Some(decision) => {
                    trace!("Cache hit for request");
                    decision
                }
                None => {
                    let evaluator = PolicyEvaluator::with_policies(self.policies().await);

                    let res = evaluator
                        .evaluate(&request)
                        .inspect_err(|e| error!(error = %e, "Error evaluating policies"))?;
                    // store the result in the cache
                    {
                        let mut cache = self.result_cache.write().await;
                        cache.insert(hashed_request, CachedResult::new(res.clone(), Utc::now()));
                    }
                    res
                }
            }
        };
        debug!(decision = %res.decision, context = ?res.context, matched_statements = ?res.matched_statements, "Finished evaluating result");
        Ok((Some(res.clone()), res.decision))
    }

    /// Get the number of loaded policies
    pub async fn policy_count(&self) -> usize {
        self.policies.read().await.len()
    }

    pub async fn policies(&self) -> Vec<IAMPolicy> {
        self.policies
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>()
    }

    /// Get all policy names
    pub async fn get_policy_names(&self) -> Vec<String> {
        let policies = self.policies.read().await;
        let mut names: Vec<String> = policies.keys().cloned().collect();
        names.sort();
        names
    }

    pub fn policy_path(&self, name: &str) -> Result<PathBuf, CrabCakesError> {
        if !self.is_valid_name(name) {
            return Err(CrabCakesError::InvalidPolicyName);
        }
        Ok(self.policy_dir.join(format!("{}.json", name)))
    }

    /// Validate a policy name to prevent path traversal
    pub fn is_valid_name(&self, name: &str) -> bool {
        !(name.contains("..") || name.contains('/') || name.contains('\\'))
            && self
                .policy_dir
                .join(format!("{}.json", name))
                .starts_with(&self.policy_dir)
            && NAME_VALIDATOR.is_match(name)
    }

    /// Get a policy by name
    pub async fn get_policy(&self, name: &str) -> Option<IAMPolicy> {
        self.policies.read().await.get(name).cloned()
    }

    /// Add a new policy
    pub async fn add_policy(&self, name: &str, policy: IAMPolicy) -> Result<(), CrabCakesError> {
        // Validate policy name (no path traversal)
        if !self.is_valid_name(name) {
            return Err(CrabCakesError::InvalidPolicyName);
        }

        // Check if policy already exists
        {
            let policies = self.policies.read().await;
            if policies.contains_key(name) {
                return Err(CrabCakesError::other(&format!(
                    "Policy '{}' already exists",
                    name
                )));
            }
        }

        // Write to file
        let policy_path = self.policy_dir.join(format!("{}.json", name));
        if !policy_path.starts_with(&self.policy_dir) {
            error!("Attempted path traversal in policy creation: {}", name);
            return Err(CrabCakesError::InvalidPath);
        }
        let policy_json = fix_mock_id(&serde_json::to_string_pretty(&policy)?);

        fs::write(&policy_path, &policy_json)
        .await.inspect_err(|e| error!(policy_path = policy_path.display().to_string(), error = %e, "Failed to write policy to file!"))?;

        // Update in-memory store
        {
            let mut policies = self.policies.write().await;
            policies.insert(name.to_string(), serde_json::from_str(&policy_json)?);
        }

        // Clear cache
        {
            let mut cache = self.result_cache.write().await;
            cache.clear();
        }

        info!(policy_name = %name, "Added policy");
        Ok(())
    }

    /// Update an existing policy
    pub async fn update_policy(&self, name: &str, policy: IAMPolicy) -> Result<(), CrabCakesError> {
        // Validate policy name (no path traversal)
        if !self.is_valid_name(name) {
            return Err(CrabCakesError::InvalidPolicyName);
        }

        // Check if policy exists
        {
            let policies = self.policies.read().await;
            if !policies.contains_key(name) {
                return Err(CrabCakesError::InvalidPolicyName);
            }
        }

        // Write to file
        let policy_path = self.policy_dir.join(format!("{}.json", name));

        let policy_json = serde_json::to_string_pretty(&policy)?;
        fs::write(&policy_path, policy_json).await?;

        // Update in-memory store
        {
            let mut policies = self.policies.write().await;
            policies.insert(name.to_string(), policy);
        }

        // Clear cache
        {
            let mut cache = self.result_cache.write().await;
            cache.clear();
        }

        info!(policy_name = %name, "Updated policy");
        Ok(())
    }

    /// Delete a policy
    pub async fn delete_policy(&self, name: &str) -> Result<(), CrabCakesError> {
        // Validate policy name (no path traversal)
        if !self.is_valid_name(name) {
            return Err(CrabCakesError::InvalidPolicyName);
        }

        // Check if policy exists
        {
            let policies = self.policies.read().await;
            if !policies.contains_key(name) {
                return Err(CrabCakesError::other(&format!(
                    "Policy '{}' not found",
                    name
                )));
            }
        }

        // Delete file
        let policy_path = self.policy_dir.join(format!("{}.json", name));
        if !policy_path.starts_with(&self.policy_dir) {
            error!("Attempted path traversal in policy deletion: {}", name);
            return Err(CrabCakesError::InvalidPath);
        }
        fs::remove_file(&policy_path).await?;

        // Remove from in-memory store
        {
            let mut policies = self.policies.write().await;
            policies.remove(name);
        }

        // Clear cache
        {
            let mut cache = self.result_cache.write().await;
            cache.clear();
        }

        info!(policy_name = %name, "Deleted policy");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_invalid_name() {
        let (_tempdir, store) = super::PolicyStore::new_test().await;
        for name in [
            "valid-name",
            "another_valid_name123",
            "validName",
            "validname",
            "valid123Name",
        ] {
            assert!(store.is_valid_name(name), "should be a valid name");
        }
        for name in [
            "-another_invalid_name123",
            "another_invalid_name123*",
            "another_invalid_name123*",
            "another_invalid_name123-",
            "a",
            "../etc/passwd",
            "valid/../name",
            "valid\\..\\name",
        ] {
            assert!(
                !store.is_valid_name(name),
                "name '{}' should be invalid",
                name
            );
        }
    }
}
