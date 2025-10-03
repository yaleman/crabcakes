# Crabcakes S3 API Implementation TODO

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