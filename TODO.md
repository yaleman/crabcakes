# Crabcakes S3 API Implementation TODO

## Phases to complete

### Phase 5: Web UI API Endpoints with CSRF Protection (In Progress)

- [ ] Session validation middleware for `/api/*` and `/admin/*` routes
- [ ] **CSRF Protection Implementation**
  - [ ] Add CSRF token generation (using session storage)
  - [ ] Add CSRF token validation on all POST/PUT/DELETE requests
  - [ ] GET /admin/api/csrf-token - Get CSRF token for current session
  - [ ] Add X-CSRF-Token header validation to all mutating endpoints
- [ ] **PolicyStore Mutation Support**
  - [ ] Store policy_dir path in PolicyStore
  - [ ] Add add_policy(name, policy) with file persistence
  - [ ] Add update_policy(name, policy) with file persistence
  - [ ] Add delete_policy(name) with file deletion
  - [ ] Clear cache on mutations
- [ ] **CredentialStore Mutation Support**
  - [ ] Store credentials_dir path in CredentialStore
  - [ ] Add add_credential(access_key_id, secret_key) with file persistence
  - [ ] Add update_credential(...) with file persistence
  - [ ] Add delete_credential(access_key_id) with file deletion
- [ ] **Policy CRUD API Endpoints**
  - [ ] GET /admin/api/policies - List all policies (read-only, no CSRF)
  - [ ] GET /admin/api/policies/{name} - Get policy details (read-only, no CSRF)
  - [ ] POST /admin/api/policies - Create policy (requires CSRF token)
  - [ ] PUT /admin/api/policies/{name} - Update policy (requires CSRF token)
  - [ ] DELETE /admin/api/policies/{name} - Delete policy (requires CSRF token)
- [ ] **Credential CRUD API Endpoints**
  - [ ] GET /admin/api/credentials - List all credentials (read-only, no CSRF)
  - [ ] POST /admin/api/credentials - Create credential (requires CSRF token)
  - [ ] PUT /admin/api/credentials/{access_key} - Update credential (requires CSRF token)
  - [ ] DELETE /admin/api/credentials/{access_key} - Delete credential (requires CSRF token)

### Phase 8: Admin UI Implementation

- [ ] Build policy management UI (list, create, edit, delete)

### Phase 9: Build System Integration

- [ ] Update justfile with frontend-install, frontend-lint, frontend-build
- [ ] Update check recipe to include frontend linting
- [ ] Add .gitignore entries for web/node_modules/, web/dist/
- [ ] Update CLAUDE.md with frontend dev instructions

## URL Structure (when API is enabled, i.e, OAuth is enabled)

- `/admin/*` - Admin UI (SPA)
- `/api/*` - API endpoints (JSON)
- `/login` - OIDC login
- `/oauth2/callback` - OIDC callback
- `/logout` - Logout
- `/*` - S3 API

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
- [ ] Enable dual-stack (IPv4/IPv6) listening support
- [ ] policy suggester - enable the mode, take some actions, and get suggestions as to what's missing from policy
  - [ ] this stores all actions while it's running (maybe in the database?) for later reference
- [ ] regular database vacuum with a record of when it was last done, so if it's overdue or really needs it, then just run the task
- [ ] turn on consistency features for sqlite to handle crashes better if there are some
- [ ] possibly look at offering postgresql as a database backend

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
