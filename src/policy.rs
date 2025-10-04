//! IAM policy storage and evaluation.
//!
//! Loads JSON IAM policies and evaluates requests against them with caching support.

use std::fs;
use std::path::PathBuf;
use std::{collections::HashMap, sync::Arc};

use iam_rs::{
    Decision, IAMAction, IAMEffect, IAMPolicy, IAMRequest, IAMResource, Principal,
    evaluate_policies,
};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::error::CrabCakesError;

fn hash_request(request: &IAMRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{:?}", request.principal));
    hasher.update(&request.action);
    hasher.update(request.resource.to_string());
    // Note: Context is not included in the hash for simplicity
    format!("{:x}", hasher.finalize())
}

pub struct PolicyStore {
    policies: HashMap<String, IAMPolicy>,
    result_cache: Arc<RwLock<HashMap<String, Decision>>>,
}

impl PolicyStore {
    /// Create a new PolicyStore by loading policies from the given directory
    pub fn new(policy_dir: &PathBuf) -> Result<Self, CrabCakesError> {
        let mut policies = HashMap::new();

        if !policy_dir.exists() {
            warn!(policy_dir = ?policy_dir, "Policy directory does not exist, can't start without policies");
            return Err(CrabCakesError::NoPolicies);
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
            policies,
            result_cache: Arc::new(RwLock::new(Default::default())),
        })
    }

    /// Load a single policy from a JSON file
    fn load_policy(path: &PathBuf) -> Result<IAMPolicy, CrabCakesError> {
        let contents = fs::read_to_string(path)?;
        let policy: IAMPolicy = serde_json::from_str(&contents)?;
        Ok(policy)
    }

    /// Evaluate a request against all loaded policies
    /// Returns true if the request is allowed, false if denied or no policy matches
    pub async fn evaluate_request(&self, request: &IAMRequest) -> Result<bool, CrabCakesError> {
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
            for policy in self.policies.values() {
                // Check each statement in the policy
                for statement in &policy.statement {
                    // Check if this statement allows the action and resource
                    // For anonymous access, we look for statements with Principal: "*"
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
                                        resource == &request.resource.to_string()
                                            || resource == "*"
                                            || resource == "arn:aws:s3:::*"
                                    }
                                    Some(IAMResource::Multiple(resources)) => {
                                        resources.iter().any(|r| {
                                            r == &request.resource.to_string()
                                                || r == "*"
                                                || r == "arn:aws:s3:::*"
                                        })
                                    }
                                    _ => false,
                                };

                                if resource_matches {
                                    debug!("Anonymous request allowed by policy");
                                    return Ok(true);
                                }
                            }
                        }
                    }
                }
            }

            debug!("No policy allows anonymous access for this request");
            return Ok(false);
        }

        // check for a result in the cache
        let hashed_request = hash_request(request);
        let res = {
            let cache = self.result_cache.read().await;
            if let Some(cached_result) = cache.get(&hashed_request) {
                debug!("Cache hit for request");
                cached_result.clone()
            } else {
                drop(cache);
                let res = evaluate_policies(&self.policies(), request)
                    .inspect_err(|e| error!(error = %e, "Error evaluating policies"))?;
                // store the result in the cache
                {
                    let mut cache = self.result_cache.write().await;
                    cache.insert(hashed_request, res.clone());
                }
                res
            }
        };

        match res {
            Decision::Allow => {
                debug!("Request allowed by policies");
                Ok(true)
            }
            Decision::Deny => {
                debug!("Request explicitly denied by policies");
                Ok(false)
            }
            Decision::NotApplicable => {
                debug!("No applicable policies found for request");
                Ok(false)
            }
        }
    }

    /// Get the number of loaded policies
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    pub fn policies(&self) -> Vec<IAMPolicy> {
        self.policies.values().cloned().collect::<Vec<_>>()
    }

    /// Get all policy names
    pub fn get_policy_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.policies.keys().cloned().collect();
        names.sort();
        names
    }

    /// Get a policy by name
    pub fn get_policy(&self, name: &str) -> Option<&IAMPolicy> {
        self.policies.get(name)
    }
}
