# Crabcakes S3 API Implementation TODO

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
