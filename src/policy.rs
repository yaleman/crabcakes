//! IAM policy storage and evaluation.
//!
//! Loads JSON IAM policies and evaluates requests against them with caching support.
use std::path::PathBuf;
use std::{collections::HashMap, sync::Arc};

use chrono::{DateTime, Utc};
use iam_rs::{
    Decision, IAMAction, IAMEffect, IAMPolicy, IAMRequest, IAMResource, IAMStatement, Principal,
    PrincipalId, Validate, evaluate_policies,
};
use sha2::{Digest, Sha256};
use std::fs;
use tokio::sync::RwLock;
use tracing::{debug, error, info, trace, warn};

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
    decision: Decision,
    timestamp: DateTime<Utc>,
}

impl CachedResult {
    pub fn new(decision: Decision, timestamp: DateTime<Utc>) -> Self {
        Self {
            decision,
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

    pub async fn get_cached_result(&self, request: &IAMRequest) -> Option<Decision> {
        let hashed_request: String = hash_request(request);
        let mut cache = self.result_cache.write().await;
        if let Some(cached_result) = cache.get(&hashed_request) {
            if !cached_result.expired(*self.expiry_secs.read().await) {
                debug!("Cache hit for request");
                return Some(cached_result.decision);
            } else {
                debug!("Cache entry expired for request");
                cache.remove(&hashed_request);
            }
        }
        None
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
            let policies = self.policies.read().await;
            for policy in policies.values() {
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
            let cached_result = self.get_cached_result(request).await;
            match cached_result {
                Some(decision) => {
                    debug!("Cache hit for request");
                    decision
                }
                None => {
                    let policies = self.policies().await;
                    let res = evaluate_policies(&policies, request)
                        .inspect_err(|e| error!(error = %e, "Error evaluating policies"))?;
                    // store the result in the cache
                    {
                        let mut cache = self.result_cache.write().await;
                        cache.insert(hashed_request, CachedResult::new(res, Utc::now()));
                    }
                    res
                }
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
            return Err(CrabCakesError::other(&"Invalid policy name"));
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
            return Err(CrabCakesError::other(&"Invalid policy path"));
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

pub(crate) trait EvaluateStatement {
    fn matches(&self, request: &IAMRequest, policy_id: &Option<String>) -> Option<Decision>;
}

impl EvaluateStatement for IAMStatement {
    fn matches(&self, request: &IAMRequest, policy_id: &Option<String>) -> Option<Decision> {
        debug!(policy_id=?policy_id, statement_id=?self.sid, "Evaluating statement");

        let _request_principal = match &request.principal {
            Principal::Aws(id) => id.to_owned(),
            _ => {
                warn!("Request principal is not AWS");
                return None;
            }
        };

        let not_principal_matches = match &self.not_principal {
            Some(not_principal) => not_principal.matches(&request.principal),
            None => false,
        };
        let principal_matches = match &self.principal {
            Some(principal) => principal.matches(&request.principal),
            None => false,
        };

        let action_matches = match &self.action {
            Some(IAMAction::Single(action)) => {
                action == &request.action || action == "*" || action == "s3:*"
            }
            Some(IAMAction::Multiple(actions)) => actions
                .iter()
                .any(|a| a == &request.action || a == "*" || a == "s3:*"),
            _ => false,
        };
        let not_action_matches = match &self.not_action {
            Some(IAMAction::Single(action)) => {
                action == &request.action || action == "*" || action == "s3:*"
            }
            Some(IAMAction::Multiple(actions)) => actions
                .iter()
                .any(|a| a == &request.action || a == "*" || a == "s3:*"),
            _ => false,
        };

        let mut decision = None;
        if (!not_principal_matches || principal_matches) && (!not_action_matches || action_matches)
        {
            decision = match self.effect {
                IAMEffect::Allow => Some(Decision::Allow),
                IAMEffect::Deny => Some(Decision::Deny),
            };
        }

        decision
    }
}

pub(crate) trait EvaluatePolicy {
    fn matches(&self, request: &IAMRequest) -> Option<Decision>;
}

impl EvaluatePolicy for IAMPolicy {
    fn matches(&self, request: &IAMRequest) -> Option<Decision> {
        let mut validation_context = iam_rs::ValidationContext::new();
        if IAMAction::Single(request.action.clone())
            .validate(&mut validation_context)
            .is_err()
        {
            warn!(action = %request.action, policy_id=?self.id, "Invalid action format");
            return Some(Decision::NotApplicable);
        }

        let mut matched_allow = false;
        for statement in self.statement.iter() {
            match statement.matches(request, &self.id) {
                Some(Decision::Deny) => return Some(Decision::Deny),
                Some(Decision::Allow) => matched_allow = true,
                _ => {}
            }
        }
        if matched_allow {
            Some(Decision::Allow)
        } else {
            Some(Decision::NotApplicable)
        }
    }
}

pub(crate) trait PrincipalMatch {
    fn matches(&self, principal: &Principal) -> bool;
}

impl PrincipalMatch for Principal {
    fn matches(&self, principal: &Principal) -> bool {
        match self {
            Principal::Aws(id) => match principal {
                Principal::Aws(other_id) => id.matches(other_id),
                _ => false,
            },
            Principal::Federated(id) => match principal {
                Principal::Federated(other_id) => id.matches(other_id),
                _ => false,
            },
            Principal::Service(id) => match principal {
                Principal::Service(other_id) => id.matches(other_id),
                _ => false,
            },
            Principal::CanonicalUser(id) => match principal {
                Principal::CanonicalUser(other_id) => id.matches(other_id),
                _ => false,
            },
            Principal::Wildcard => true,
        }
    }
}

pub(crate) trait PrincipalIdMatch {
    fn matches(&self, principal: &PrincipalId) -> bool;
}

impl PrincipalIdMatch for PrincipalId {
    fn matches(&self, principal: &PrincipalId) -> bool {
        match self {
            // if we're an array, drop down to a single-single comparison
            PrincipalId::Array(arr) => arr
                .iter()
                .any(|p| PrincipalId::String(p.to_owned()).matches(principal)),
            PrincipalId::String(self_as_string) => match principal {
                // if the other side's an array, drop down to a single-single comparison
                PrincipalId::Array(arr) => arr
                    .iter()
                    .any(|p| self.matches(&PrincipalId::String(p.to_owned()))),
                // here's the only one we need to implement!
                PrincipalId::String(other) => {
                    // easy cases first
                    if self_as_string == other
                        || self_as_string == "*"
                        || other == "*"
                        || other.ends_with(":*")
                        || self_as_string.ends_with(":*")
                        || other.ends_with(":user/*")
                        || self_as_string.ends_with(":user/*")
                    {
                        true
                    } else {
                        if self_as_string.ends_with("*") {
                            let prefix = &self_as_string[..self_as_string.len() - 1];
                            if other.starts_with(prefix) {
                                return true;
                            }
                        } else if other.ends_with("*") {
                            let prefix = &other[..other.len() - 1];
                            if self_as_string.starts_with(prefix) {
                                return true;
                            }
                        }
                        trace!(
                            left = self_as_string,
                            right = other,
                            "PrincipalId::matches may need to handle other cases"
                        );
                        false
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use iam_rs::{Arn, Context, IAMVersion};

    use crate::setup_test_logging;

    use super::*;

    #[test]
    fn principal_matches_wildcards() {
        setup_test_logging();
        let principal = PrincipalId::String("arn:aws:iam::123456789012:user/Alice".into());
        assert!(
            PrincipalId::String("arn:aws:iam::123456789012:user/Alice".into()).matches(&principal)
        );
        assert!(PrincipalId::String("arn:aws:iam::123456789012:user/*".into()).matches(&principal));
        assert!(PrincipalId::String("arn:aws:iam::123456789012:*".into()).matches(&principal));
        assert!(PrincipalId::String("arn:aws:iam::*".into()).matches(&principal));
        assert!(PrincipalId::String("*".into()).matches(&principal));
        assert!(
            !PrincipalId::String("arn:aws:iam::123456789012:user/Bob".into()).matches(&principal)
        );
        assert!(
            !PrincipalId::String("arn:aws:s3:::my_corporate_bucket/*".into()).matches(&principal)
        );
    }

    #[test]
    fn principal_matches_other() {
        setup_test_logging();
        let left = PrincipalId::String("arn:aws:iam::123456789012:user/Alice*".into());
        let right = PrincipalId::String("arn:aws:iam::123456789012:user/Alice".into());
        assert!(left.matches(&right));
        assert!(right.matches(&left));
    }

    #[test]
    fn policy_evaluate_invalid_request_action() {
        setup_test_logging();
        let policy = IAMPolicy {
            id: Some("TestPolicy".into()),
            version: IAMVersion::V20121017,
            statement: vec![IAMStatement {
                sid: Some("Stmt1".into()),
                effect: IAMEffect::Allow,
                principal: Some(Principal::Aws(PrincipalId::String(
                    "arn:aws:iam::123456789012:user/Alice".into(),
                ))),
                not_principal: None,
                action: Some(IAMAction::Single("S3:GetObjects".into())),
                not_action: None,
                resource: Some(IAMResource::Single(
                    "arn:aws:s3:::my_corporate_bucket/*".into(),
                )),
                not_resource: None,
                condition: None,
            }],
        };

        let request = IAMRequest {
            principal: Principal::Aws(PrincipalId::String(
                "arn:aws:iam::123456789012:user/Alice".into(),
            )),
            action: "Crabcakes".into(),
            resource: Arn::parse("arn:aws:s3:::my_corporate_bucket/myfile.txt")
                .expect("Invalid ARN"),
            context: Context::new(),
        };

        let decision = policy.matches(&request);
        assert_eq!(decision, Some(Decision::NotApplicable));
    }
}
