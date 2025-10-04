# Crabcakes S3 API Implementation TODO

## Web Admin UI Implementation (In Progress)

### Phase 4: OIDC/OAuth2 with PKCE Authentication
- [x] Add Rust dependencies: openidconnect, rand, tower-sessions, tower-sessions-sqlx-store
- [ ] Create src/auth/ module structure
- [ ] Create src/auth/oauth.rs for OIDC client and PKCE flow
- [ ] Implement GET /login - Generate PKCE challenge, redirect to OIDC provider
- [ ] Implement GET /oauth2/callback - Exchange code for tokens, create session
- [ ] Implement POST /logout - Delete session and temp credentials
- [ ] Create session cookie (HTTP-only, Secure, SameSite)
- [ ] Generate temporary AWS credentials on successful login
- [ ] Extract user info from ID token (email, sub)

### Phase 5: Web UI API Endpoints
- [ ] Create src/web_handlers.rs for web UI routes
- [ ] Session validation middleware for /api/* and /admin/* routes
- [ ] GET /api/credentials - List all permanent credentials
- [ ] POST /api/credentials - Create new permanent credential
- [ ] DELETE /api/credentials/{access_key_id} - Delete credential
- [ ] GET /api/policies - List all policies
- [ ] GET /api/policies/{name} - Get policy details
- [ ] POST /api/policies - Create/update policy
- [ ] DELETE /api/policies/{name} - Delete policy
- [ ] GET /api/session - Get current session with temp credentials

### Phase 6: Routing & Request Dispatch
- [ ] Update server.rs::run() to dispatch based on disable_api flag
- [ ] Route /admin/* to SPA (index.html from web/dist/)
- [ ] Route /api/* to API handlers with session auth
- [ ] Route /login, /logout, /oauth2/* to OAuth handlers
- [ ] Serve static assets from web/dist/assets/
- [ ] Fallback /admin/* to index.html (SPA routing)

### Phase 7: TypeScript Frontend Setup
- [ ] Create web/ directory with pnpm create vite
- [ ] Configure Vite for /admin/ base path
- [ ] Setup Tailwind CSS
- [ ] Setup shadcn/ui components
- [ ] Add React Router with BrowserRouter (basename="/admin")
- [ ] Add ESLint + Prettier
- [ ] Add AWS SDK for JavaScript (@aws-sdk/client-s3)

### Phase 8: React Admin UI Implementation
- [ ] Setup routes: /, /credentials, /policies, /policies/:name
- [ ] Create TypeScript types for API responses
- [ ] Implement auth flow (login redirect, session fetch, credential storage)
- [ ] Create API client utility for /api/* calls
- [ ] Setup AWS S3 client with temp credentials from LocalStorage
- [ ] Build credentials management UI (table, create/delete)
- [ ] Build policy management UI (list, create, edit, delete)
- [ ] Ensure all navigation updates URL for deep linking

### Phase 9: Build System Integration
- [ ] Update justfile with frontend-install, frontend-lint, frontend-build
- [ ] Update check recipe to include frontend linting
- [ ] Add .gitignore entries for web/node_modules/, web/dist/
- [ ] Update CLAUDE.md with frontend dev instructions

## Environment Variables (Admin UI)
- `CRABCAKES_DISABLE_API` - Disable admin UI and API (default: false, API enabled by default)
- `CRABCAKES_OIDC_CLIENT_ID` - OAuth client ID (required if API enabled)
- `CRABCAKES_OIDC_DISCOVERY_URL` - OIDC discovery URL (required if API enabled)

## URL Structure (when API is enabled, i.e., CRABCAKES_DISABLE_API=false)
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
- [ ] Design ACL storage (similar to tags, use sidecar files)
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

## Completed Phases (24 Operations)

All phases 0-4 are complete:
- ✅ Phase 0: Configuration Enhancement (region support)
- ✅ Phase 1: Core Operations (DeleteObjects, CopyObject, GetBucketLocation, ListObjectsV1)
- ✅ Phase 2: Multipart Upload Foundation (CreateMultipartUpload, UploadPart, AbortMultipartUpload, ListMultipartUploads, ListParts)
- ✅ Phase 3: Multipart Upload Completion (CompleteMultipartUpload, UploadPartCopy)
- ✅ Phase 4: Object Tagging (PutObjectTagging, GetObjectTagging, DeleteObjectTagging, GetObjectAttributes)

See git history for implementation details.