use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use iam_rs::{Decision, IAMPolicy, IAMRequest, evaluate_policies};
use tracing::{debug, error, info, warn};

use crate::error::CrabCakesError;

pub struct PolicyStore {
    policies: HashMap<String, IAMPolicy>,
}

impl PolicyStore {
    /// Create a new PolicyStore by loading policies from the given directory
    pub fn new(policy_dir: PathBuf) -> Result<Self, CrabCakesError> {
        let mut policies = HashMap::new();

        info!(policy_dir = ?policy_dir, "Loading IAM policies");

        if !policy_dir.exists() {
            warn!(policy_dir = ?policy_dir, "Policy directory does not exist, starting with no policies");
            return Ok(Self { policies });
        }

        if !policy_dir.is_dir() {
            error!(policy_dir = ?policy_dir, "Policy path is not a directory");
            return Err(CrabCakesError::other("Policy path is not a directory"));
        }

        // Read all JSON files from the policy directory
        for entry in fs::read_dir(&policy_dir)? {
            let entry = entry.inspect_err(|err| debug!("Failed to read {:?}", err))?;
            let path = entry.path();

            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                match Self::load_policy(&path) {
                    Ok(policy) => {
                        let policy_name = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown")
                            .to_string();
                        info!(policy_name = %policy_name, path = ?path, "Loaded policy");
                        policies.insert(policy_name, policy);
                    }
                    Err(e) => {
                        error!(path = ?path, error = %e, "Failed to load policy");
                    }
                }
            }
        }

        info!(count = policies.len(), "Loaded IAM policies");
        Ok(Self { policies })
    }

    /// Load a single policy from a JSON file
    fn load_policy(path: &PathBuf) -> Result<IAMPolicy, CrabCakesError> {
        let contents = fs::read_to_string(path)?;
        let policy: IAMPolicy = serde_json::from_str(&contents)?;
        Ok(policy)
    }

    /// Evaluate a request against all loaded policies
    /// Returns true if the request is allowed, false if denied or no policy matches
    pub fn evaluate_request(&self, request: &IAMRequest) -> Result<bool, CrabCakesError> {
        // AWS IAM evaluation logic:
        // 1. Default deny
        // 2. Check all policies
        // 3. Explicit deny wins over allow
        // 4. At least one allow is needed (unless there's an explicit deny)

        debug!(
            principal = ?request.principal,
            action = %request.action,
            resource = %request.resource,
            "Evaluating request"
        );

        // TODO: check if there's a wildcard/anonymous request and check if the resource/action matches the policy.

        match evaluate_policies(&self.policies(), request).inspect_err(|e| {
            error!(error = %e, "Error evaluating policies");
        })? {
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
}
