# Crabcakes S3 API Implementation TODO

## PRIORITY: API Handler Refactoring for Testability

**Status:** Not Started
**Priority:** HIGH - Blocks comprehensive test coverage
**Estimated Time:** 6-8 hours

### Overview

Extract business logic from 11 API endpoint handlers in `WebHandler` into separate testable methods in `RequestHandler`. This follows the existing pattern established with `RequestHandler::api_troubleshooter()` and `RequestHandler::api_delete_bucket()`.

**Goal:** Enable direct unit testing of business logic without complex HTTP `Request<Incoming>` setup, while maintaining comprehensive integration tests for authentication, CSRF validation, and request parsing.

### Current Pattern (Already Implemented)

#### Example: Policy Troubleshooter
```rust
// src/web/handlers.rs
async fn post_api_policy_troubleshooter(&self, req: Request<Incoming>, session: Session) {
    self.check_auth(&session).await?;  // HTTP concern
    let (parts, body) = req.into_parts();  // HTTP parsing
    self.validate_csrf_token(&session, &parts.headers).await?;  // CSRF validation
    let form: TroubleShooterForm = self.parse_json_body(body).await?;  // HTTP parsing

    // Call extracted business logic
    let response = self.request_handler.api_troubleshooter(form).await?;

    self.build_json_response(serde_json::to_value(response)?)  // HTTP response
}

// src/request_handler.rs
pub(crate) async fn api_troubleshooter(
    &self,
    form: TroubleShooterForm,
) -> Result<TroubleShooterResponse, CrabCakesError> {
    // Pure business logic - no HTTP concerns
    // Fully testable without HTTP request setup
    // ...
}
```

### Handlers Requiring Extraction

#### 1. Bucket Operations (1 handler)

**Handler:** `post_api_bucket` (src/web/handlers.rs)

**New Method Signature:**
```rust
// src/request_handler.rs
pub(crate) async fn api_create_bucket(
    &self,
    bucket_name: &str,
) -> Result<(), CrabCakesError>
```

**Business Logic:**
- Validate bucket name (DNS compliance, 1-63 chars, lowercase, no special chars)
- Check against reserved names (admin, api, login, logout, oauth2, .well-known, config, oidc, crabcakes, docs, help)
- Check if bucket already exists
- Create bucket directory via `filesystem.create_bucket()`

**Tests Needed:**
- Valid bucket name creation
- Invalid bucket name (uppercase, special chars, too long)
- Reserved bucket name rejection
- Duplicate bucket name conflict

---

#### 2. Policy Operations (4 handlers)

**Handler:** `handle_api_list_policies` (src/web/handlers.rs)

**New Method Signature:**
```rust
pub(crate) async fn api_list_policies(&self) -> Result<Vec<PolicyInfo>, CrabCakesError>

// Where PolicyInfo is:
#[derive(Serialize)]
pub struct PolicyInfo {
    pub name: String,
    pub policy: serde_json::Value,
}
```

**Business Logic:**
- Read all policies from `policy_store.policies`
- Map to `PolicyInfo` structs with name and policy JSON
- Return sorted by name

**Tests Needed:**
- List empty policies
- List multiple policies
- Verify policy JSON structure

---

**Handler:** `handle_api_create_policy` (src/web/handlers.rs)

**New Method Signature:**
```rust
pub(crate) async fn api_create_policy(
    &self,
    name: String,
    policy_json: serde_json::Value,
) -> Result<(), CrabCakesError>
```

**Business Logic:**
- Validate policy name (non-empty, valid characters)
- Parse policy JSON as `iam_rs::Policy`
- Check for duplicate policy name
- Write policy file to `config_dir/policies/{name}.json`
- Reload policies via `policy_store.load_policies()`

**Tests Needed:**
- Valid policy creation
- Invalid policy JSON structure
- Duplicate policy name
- Policy file write failure

---

**Handler:** `handle_api_update_policy` (src/web/handlers.rs)

**New Method Signature:**
```rust
pub(crate) async fn api_update_policy(
    &self,
    name: String,
    policy_json: serde_json::Value,
) -> Result<(), CrabCakesError>
```

**Business Logic:**
- Validate policy name exists
- Parse policy JSON as `iam_rs::Policy`
- Update policy file at `config_dir/policies/{name}.json`
- Reload policies via `policy_store.load_policies()`

**Tests Needed:**
- Update existing policy
- Update nonexistent policy (error)
- Invalid policy JSON
- Policy file write failure

---

**Handler:** `handle_api_delete_policy` (src/web/handlers.rs)

**New Method Signature:**
```rust
pub(crate) async fn api_delete_policy(
    &self,
    name: String,
) -> Result<(), CrabCakesError>
```

**Business Logic:**
- Validate policy name exists
- Delete policy file at `config_dir/policies/{name}.json`
- Reload policies via `policy_store.load_policies()`

**Tests Needed:**
- Delete existing policy
- Delete nonexistent policy (should succeed idempotently)
- Policy file delete failure

---

#### 3. Credential Operations (4 handlers)

**Handler:** `get_api_credentials` (src/web/handlers.rs)

**New Method Signature:**
```rust
pub(crate) async fn api_list_credentials(&self) -> Result<Vec<CredentialInfo>, CrabCakesError>

// Where CredentialInfo is:
#[derive(Serialize)]
pub struct CredentialInfo {
    pub access_key_id: String,
    // DO NOT include secret_access_key in response
}
```

**Business Logic:**
- Read all credentials from `credentials_store`
- Map to `CredentialInfo` structs (access_key_id only)
- Return sorted by access_key_id

**Tests Needed:**
- List empty credentials
- List multiple credentials
- Verify secret keys not exposed

---

**Handler:** `post_api_credential` (src/web/handlers.rs)

**New Method Signature:**
```rust
pub(crate) async fn api_create_credential(
    &self,
    access_key_id: String,
    secret_access_key: String,
) -> Result<(), CrabCakesError>
```

**Business Logic:**
- Validate access_key_id (non-empty, valid characters)
- Validate secret_access_key (non-empty, sufficient length)
- Check for duplicate access_key_id
- Write credential file to `config_dir/credentials/{access_key_id}.json`
- Reload credentials via `credentials_store.load_credentials()`

**Tests Needed:**
- Valid credential creation
- Invalid access_key_id (empty, special chars)
- Duplicate access_key_id
- Weak secret_access_key (too short)
- Credential file write failure

---

**Handler:** `put_api_credential` (src/web/handlers.rs)

**New Method Signature:**
```rust
pub(crate) async fn api_update_credential(
    &self,
    access_key_id: String,
    secret_access_key: String,
) -> Result<(), CrabCakesError>
```

**Business Logic:**
- Validate access_key_id exists
- Validate secret_access_key (non-empty, sufficient length)
- Update credential file at `config_dir/credentials/{access_key_id}.json`
- Reload credentials via `credentials_store.load_credentials()`

**Tests Needed:**
- Update existing credential
- Update nonexistent credential (error)
- Weak secret_access_key
- Credential file write failure

---

**Handler:** `delete_api_credential` (src/web/handlers.rs)

**New Method Signature:**
```rust
pub(crate) async fn api_delete_credential(
    &self,
    access_key_id: String,
) -> Result<(), CrabCakesError>
```

**Business Logic:**
- Validate access_key_id exists
- Delete credential file at `config_dir/credentials/{access_key_id}.json`
- Reload credentials via `credentials_store.load_credentials()`

**Tests Needed:**
- Delete existing credential
- Delete nonexistent credential (should succeed idempotently)
- Credential file delete failure

---

#### 4. Temporary Credential Operations (1 handler)

**Handler:** `delete_api_temp_credential` (src/web/handlers.rs)

**New Method Signature:**
```rust
pub(crate) async fn api_delete_temp_credential(
    &self,
    access_key_id: String,
) -> Result<(), CrabCakesError>
```

**Business Logic:**
- Delete temporary credential from database via `db.delete_temporary_credentials(access_key_id)`
- Return Ok(()) even if credential doesn't exist (idempotent)

**Tests Needed:**
- Delete existing temp credential
- Delete nonexistent temp credential (succeeds)
- Database error handling

---

#### 5. Database Operations (2 handlers)

**Handler:** `get_api_database_vacuum` (src/web/handlers.rs)

**New Method Signature:**
```rust
pub(crate) async fn api_database_vacuum_status(&self) -> Result<VacuumStats, CrabCakesError>

// Where VacuumStats is:
#[derive(Serialize)]
pub struct VacuumStats {
    pub page_count: i64,
    pub page_size: i64,
    pub freelist_count: i64,
    pub total_size_bytes: i64,
    pub freelist_size_bytes: i64,
}
```

**Business Logic:**
- Query SQLite for vacuum statistics:
  - `PRAGMA page_count`
  - `PRAGMA page_size`
  - `PRAGMA freelist_count`
- Calculate total_size_bytes and freelist_size_bytes
- Return statistics struct

**Tests Needed:**
- Get vacuum stats from empty database
- Get vacuum stats from database with data
- Database query error handling

---

**Handler:** `post_api_database_vacuum` (src/web/handlers.rs)

**New Method Signature:**
```rust
pub(crate) async fn api_database_vacuum(
    &self,
    confirm: bool,
) -> Result<VacuumResult, CrabCakesError>

// Where VacuumResult is:
#[derive(Serialize)]
pub struct VacuumResult {
    pub success: bool,
    pub pages_freed: i64,
}
```

**Business Logic:**
- Validate `confirm == true` (error if false)
- Get pre-vacuum statistics
- Execute `VACUUM` on database
- Get post-vacuum statistics
- Calculate pages freed
- Return result struct

**Tests Needed:**
- Execute vacuum with confirm=true
- Reject vacuum with confirm=false
- Verify pages freed calculation
- Database vacuum error handling

---

### Implementation Phases

#### Phase 1: Define Serde Types (1 hour)

Add new types to `src/web/serde.rs`:
- `PolicyInfo` - For policy listing
- `CredentialInfo` - For credential listing (without secrets)
- `VacuumStats` - For database vacuum statistics
- `VacuumResult` - For database vacuum execution result

#### Phase 2: Extract RequestHandler Methods (3 hours)

Add 11 new methods to `src/request_handler.rs`:
1. `api_create_bucket()`
2. `api_list_policies()`
3. `api_create_policy()`
4. `api_update_policy()`
5. `api_delete_policy()`
6. `api_list_credentials()`
7. `api_create_credential()`
8. `api_update_credential()`
9. `api_delete_credential()`
10. `api_delete_temp_credential()`
11. `api_database_vacuum_status()`
12. `api_database_vacuum()`

Each method should:
- Accept simple parameters (strings, bools, parsed JSON)
- Return typed results (structs, units)
- Contain only business logic
- Have no HTTP concerns (no Request, Response, Session, CSRF)

#### Phase 3: Update WebHandler Methods (2 hours)

Update 11 handlers in `src/web/handlers.rs`:
- Keep authentication checks (`check_auth`)
- Keep CSRF validation (`validate_csrf_token`)
- Keep request parsing (`parse_json_body`, query params)
- Replace business logic with `self.request_handler.api_*()` calls
- Keep response building (`build_json_response`, `build_empty_response`)

#### Phase 4: Add Unit Tests (2 hours)

Create `src/tests/request_handler_tests.rs`:
- Test each extracted method with positive cases
- Test each extracted method with negative cases
- Test error conditions (invalid input, missing resources, database errors)
- Use in-memory database for database operations
- Use temporary directories for file operations

**Estimated test count:** 40+ unit tests for business logic

### Code Estimate

- **New serde types:** ~40 lines
- **New RequestHandler methods:** ~400 lines
- **Updated WebHandler methods:** ~200 lines (refactored, less logic)
- **New unit tests:** ~600 lines
- **Total:** ~1,240 lines changed/added

### Integration Test Strategy (Post-Refactoring)

After business logic extraction, add comprehensive integration tests to `src/tests/web_handlers_tests.rs`:
- Use `reqwest` HTTP client against running test server
- Test full authentication flow (session cookies)
- Test CSRF token generation and validation
- Test all 15 API endpoints with positive/negative/unauth/CSRF failure scenarios
- **Estimated test count:** 68+ integration tests

### Success Criteria

1. All 11 API handlers have business logic extracted to RequestHandler
2. All RequestHandler methods have direct unit tests
3. `cargo clippy --all-targets` passes with no warnings
4. `cargo test` passes all tests
5. Business logic testable without HTTP request setup
6. HTTP concerns (auth, CSRF, parsing) remain in WebHandler for integration testing

---

## Future Work

### Phase 5: ACL Operations (Optional)

**Status:** Not Started

#### Infrastructure

- [ ] Design ACL storage (similar to tags, use a database table)
- [ ] Implement ACL validation and defaults
- [ ] Support canned ACLs (private, public-read, etc.)

#### 16-19. ACL Operations

- [ ] GetObjectAcl - `GET /key?acl`
- [ ] PutObjectAcl - `PUT /key?acl`
- [ ] GetBucketAcl - `GET /bucket?acl`
- [ ] PutBucketAcl - `PUT /bucket?acl`
- [ ] Add corresponding IAM actions

**Estimated Time:** 3-4 hours

---

## Future Enhancements

### Server Infrastructure

- [ ] Investigate using shellflip crate for graceful server restarts - example implementation here <https://github.com/cloudflare/shellflip/blob/main/examples/restarter.rs>
- [ ] policy suggester - enable the mode, take some actions, and get suggestions as to what's missing from policy
  - [ ] this stores all actions while it's running (maybe in the database?) for later reference
- [ ] turn on consistency features for sqlite to handle crashes better if there are some

---

## Out of Scope (Won't Implement)

- ❌ Versioning operations
- ❌ Replication operations
- ❌ Analytics operations
- ❌ Lifecycle operations
- ❌ Inventory operations
- ❌ Intelligent tiering
- ❌ Object Lock
- ❌ Legal Hold

---
