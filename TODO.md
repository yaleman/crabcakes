# Crabcakes S3 API Implementation TODO

## Phases to complete

### Phase 5: Web UI API Endpoints with CSRF Protection (COMPLETE)

- [x] Session validation middleware for `/api/*` and `/admin/*` routes
- [x] **CSRF Protection Implementation**
  - [x] Add CSRF token generation (using session storage)
  - [x] Add CSRF token validation on all POST/PUT/DELETE requests
  - [x] GET /admin/api/csrf-token - Get CSRF token for current session
  - [x] Add X-CSRF-Token header validation to all mutating endpoints

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

---

## Testing

### Policy Troubleshooter Function Tests (`handle_troubleshooter_request`)

**Test Setup:**
- Load PolicyStore from test_config/policies/testuser.json
- Create helper function to build TroubleShooterForm
- Each test calls `handle_troubleshooter_request` and asserts decision

**Allow Scenario Tests (testuser with valid access):**
- [ ] `test_troubleshooter_testuser_bucket1_testuser_prefix_allow` - s3:GetObject on bucket1/testuser/file.txt → Allow
- [ ] `test_troubleshooter_testuser_bucket1_testuser_wildcard_allow` - s3:* on bucket1/testuser/* → Allow
- [ ] `test_troubleshooter_testuser_bucket2_allow` - s3:PutObject on bucket2/file.txt → Allow
- [ ] `test_troubleshooter_testuser_bucket2_root_allow` - s3:ListBucket on bucket2 (no key) → Allow
- [ ] `test_troubleshooter_testuser_list_all_buckets_allow` - s3:ListAllMyBuckets on * → Allow
- [ ] `test_troubleshooter_testuser_list_bucket1_allow` - s3:ListBucket on bucket1 (bucket-level) → Allow
- [ ] `test_troubleshooter_testuser_create_bucket21_allow` - s3:CreateBucket on bucket21 → Allow
- [ ] `test_troubleshooter_testuser_delete_bucket21_allow` - s3:DeleteBucket on bucket21 → Allow

**Deny Scenario Tests (testuser with no access):**
- [ ] `test_troubleshooter_testuser_bucket1_other_prefix_deny` - s3:GetObject on bucket1/other/file.txt → Deny
- [ ] `test_troubleshooter_testuser_bucket3_deny` - s3:GetObject on bucket3/file.txt → Deny (no policy)
- [ ] `test_troubleshooter_testuser_bucket1_root_putobject_deny` - s3:PutObject on bucket1/file.txt → Deny (only testuser/* allowed)

**Different User Tests:**
- [ ] `test_troubleshooter_otheruser_bucket1_deny` - otheruser accessing bucket1/testuser/* → Deny
- [ ] `test_troubleshooter_otheruser_bucket2_deny` - otheruser accessing bucket2/* → Deny

**Edge Case Tests:**
- [ ] `test_troubleshooter_empty_bucket_becomes_wildcard` - Empty bucket → becomes arn:aws:s3:::*
- [ ] `test_troubleshooter_bucket_level_operation` - No key provided → tests bucket-only ARN
- [ ] `test_troubleshooter_specific_policy_filter` - Policy name set → only evaluates that policy
- [ ] `test_troubleshooter_all_policies_evaluated` - Empty policy name → evaluates all policies

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
