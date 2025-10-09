//! IAM policy storage and evaluation.
//!
//! Loads JSON IAM policies and evaluates requests against them with caching support.
use std::path::PathBuf;
use std::{collections::HashMap, sync::Arc};

use chrono::{DateTime, Utc};
use iam_rs::{
    Decision, EvaluationResult, IAMAction, IAMEffect, IAMPolicy, IAMRequest, IAMResource,
    PolicyEvaluator, Principal,
};
use sha2::{Digest, Sha256};
use std::fs;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

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

impl PolicyStore {
    /// Create a new PolicyStore by loading policies from the given directory
    pub fn new(policy_dir: &PathBuf) -> Result<Self, CrabCakesError> {
        let mut policies = HashMap::new();

        if !policy_dir.exists() {
            warn!(policy_dir = ?policy_dir, "Policy directory does not exist, creating it...");
            fs::create_dir_all(policy_dir).inspect_err(|err| {
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
        for entry in fs::read_dir(policy_dir)? {
            let entry = entry.inspect_err(|err| {
                debug!(
                    "Failed to read an entry from the policy directory:  {:?}",
                    err
                )
            })?;
            let path = entry.path();

            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                match Self::load_policy(&path) {
                    Ok(policy) => {
                        let policy_name = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown")
                            .to_string();
                        debug!(policy_name = %policy_name, path = ?path, "Loaded policy");
                        policies.insert(policy_name, policy);
                    }
                    Err(e) => {
                        error!(path = ?path, error = %e, "Failed to load policy");
                    }
                }
            }
        }

        info!(count = policies.len(), "Loaded IAM policies");
        Ok(Self {
            policies: Arc::new(RwLock::new(policies)),
            result_cache: Arc::new(RwLock::new(Default::default())),
            policy_dir: policy_dir.clone(),
            expiry_secs: Arc::new(RwLock::new(300)), // cache expiry in seconds
        })
    }

    /// Load a single policy from a JSON file
    fn load_policy(path: &PathBuf) -> Result<IAMPolicy, CrabCakesError> {
        let contents = fs::read_to_string(path)?;
        let policy: IAMPolicy = serde_json::from_str(&contents)?;
        Ok(policy)
    }

    pub async fn get_cached_result(&self, request: &IAMRequest) -> Option<EvaluationResult> {
        let hashed_request: String = hash_request(request);
        let mut cache = self.result_cache.write().await;
        if let Some(cached_result) = cache.get(&hashed_request) {
            if !cached_result.expired(*self.expiry_secs.read().await) {
                debug!("Cache hit for request");
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
        let hashed_request = hash_request(request);
        let res = {
            let cached_result = self.get_cached_result(request).await;
            match cached_result {
                Some(decision) => {
                    debug!("Cache hit for request");
                    decision
                }
                None => {
                    let evaluator = PolicyEvaluator::with_policies(self.policies().await);

                    let res = evaluator
                        .evaluate(request)
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
        debug!(result = format!("{:?}", res), "Finished evaluating result");
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

    pub fn is_valid_name(name: &str) -> bool {
        !(name.contains("..") || name.contains('/') || name.contains('\\'))
    }

    /// Get a policy by name
    pub async fn get_policy(&self, name: &str) -> Option<IAMPolicy> {
        self.policies.read().await.get(name).cloned()
    }

    /// Add a new policy
    pub async fn add_policy(&self, name: String, policy: IAMPolicy) -> Result<(), CrabCakesError> {
        // Validate policy name (no path traversal)
        if !Self::is_valid_name(&name) {
            return Err(CrabCakesError::other(&"Invalid policy name"));
        }

        // Check if policy already exists
        {
            let policies = self.policies.read().await;
            if policies.contains_key(&name) {
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
            return Err(CrabCakesError::other(&"Invalid policy path"));
        }
        let policy_json = serde_json::to_string_pretty(&policy)?;
        fs::write(&policy_path, policy_json)?;

        // Update in-memory store
        {
            let mut policies = self.policies.write().await;
            policies.insert(name.clone(), policy);
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
    pub async fn update_policy(
        &self,
        name: String,
        policy: IAMPolicy,
    ) -> Result<(), CrabCakesError> {
        // Validate policy name (no path traversal)
        if !Self::is_valid_name(&name) {
            return Err(CrabCakesError::other(&"Invalid policy name"));
        }

        // Check if policy exists
        {
            let policies = self.policies.read().await;
            if !policies.contains_key(&name) {
                return Err(CrabCakesError::other(&format!(
                    "Policy '{}' not found",
                    name
                )));
            }
        }

        // Write to file
        let policy_path = self.policy_dir.join(format!("{}.json", name));
        if !policy_path.starts_with(&self.policy_dir) {
            error!("Attempted path traversal in policy update: {}", name);
            return Err(CrabCakesError::other(&"Invalid policy path"));
        }
        let policy_json = serde_json::to_string_pretty(&policy)?;
        fs::write(&policy_path, policy_json)?;

        // Update in-memory store
        {
            let mut policies = self.policies.write().await;
            policies.insert(name.clone(), policy);
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
        if !Self::is_valid_name(name) {
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
        fs::remove_file(&policy_path)?;

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
