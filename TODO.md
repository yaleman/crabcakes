# Crabcakes S3 API Implementation TODO

## Currently Implemented Operations (9)
- ✅ ListBuckets
- ✅ ListObjectsV2
- ✅ HeadBucket
- ✅ CreateBucket
- ✅ DeleteBucket
- ✅ GetObject
- ✅ HeadObject
- ✅ PutObject
- ✅ DeleteObject

## Implementation Phases

### Phase 0: Configuration Enhancement
**Status:** ✅ Complete

- [x] Add `--region` CLI flag and `CRABCAKES_REGION` environment variable
  - Default value: `"crabcakes"`
  - Store in `Cli` struct and pass to `Server`
- [x] Update CLAUDE.md documentation with region configuration

**Completed:** Already implemented in previous work

---

### Phase 1: Core Operations
**Status:** Not Started

#### 1. DeleteObjects (Batch Delete)
- [x] Parse POST /?delete XML request body
- [x] Delete multiple objects in single request
- [x] Return XML response with deleted objects and errors
- [x] Add `s3:DeleteObject` IAM action check
- [x] Write integration test

**Status:** ✅ Complete

**Key Details:**
- Request: `POST /?delete` with XML body listing keys
- Response: XML with `<DeleteResult>` containing `<Deleted>` and `<Error>` elements
- Must be idempotent (deleting non-existent objects is success)

#### 2. CopyObject
- [x] Parse `x-amz-copy-source` header to extract source bucket/key
- [x] Implement filesystem copy operation
- [x] Return XML response with copy metadata
- [x] Add `s3:GetObject` (source) and `s3:PutObject` (dest) IAM checks
- [x] Write integration test

**Status:** ✅ Complete

**Key Details:**
- Request: `PUT /dest-key` with `x-amz-copy-source: /source-bucket/source-key` header
- Response: XML with `<CopyObjectResult>` containing `<ETag>` and `<LastModified>`
- Server-side operation (no body transfer)

#### 3. GetBucketLocation
- [x] Add query parameter detection for `?location`
- [x] Return configured region in XML response
- [x] Add `s3:GetBucketLocation` IAM action
- [x] Write integration test

**Status:** ✅ Complete

**Key Details:**
- Request: `GET /bucket?location`
- Response: XML with `<LocationConstraint>` containing region string
- Returns configured region (default: "crabcakes")

#### 4. ListObjectsV1 (Legacy API)
- [x] Detect legacy list request (GET without `list-type=2`)
- [x] Parse query parameters: `prefix`, `delimiter`, `marker`, `max-keys`
- [x] Implement pagination with `marker` (instead of `continuation-token`)
- [x] Generate V1 XML response format
- [x] Add `s3:ListBucket` IAM action check
- [x] Write integration test

**Status:** ✅ Complete

**Key Details:**
- Request: `GET /bucket?prefix=foo&max-keys=100&marker=lastkey`
- Response: V1 XML format with `<ListBucketResult>`, `<NextMarker>`, `<IsTruncated>`
- Different pagination mechanism than V2

**Estimated Time:** 2-3 hours

---

### Phase 2: Multipart Upload Foundation
**Status:** Not Started

#### Infrastructure
- [ ] Design multipart upload state storage
  - Option A: In-memory HashMap (lost on restart)
  - Option B: Filesystem directory structure (persistent)
  - Recommendation: Filesystem under `{root}/.multipart/{bucket}/{uploadId}/`
- [ ] Generate unique upload IDs (UUID)
- [ ] Store upload metadata (bucket, key, initiated time)

#### 5. CreateMultipartUpload
- [ ] Parse `POST /key?uploads` request
- [ ] Generate upload ID
- [ ] Create multipart state directory
- [ ] Return XML with `<UploadId>`
- [ ] Add `s3:PutObject` IAM action check

#### 6. UploadPart
- [ ] Parse `PUT /key?uploadId=X&partNumber=Y` request
- [ ] Validate part number (1-10000)
- [ ] Store part data with ETag
- [ ] Return ETag header
- [ ] Add `s3:PutObject` IAM action check

#### 7. AbortMultipartUpload
- [ ] Parse `DELETE /key?uploadId=X` request
- [ ] Clean up all uploaded parts
- [ ] Remove multipart state
- [ ] Return 204 No Content
- [ ] Add `s3:AbortMultipartUpload` IAM action

#### 8. ListMultipartUploads
- [ ] Parse `GET /bucket?uploads` request
- [ ] List all active uploads in bucket
- [ ] Support pagination with `key-marker` and `upload-id-marker`
- [ ] Return XML with upload list
- [ ] Add `s3:ListBucketMultipartUploads` IAM action

#### 9. ListParts
- [ ] Parse `GET /key?uploadId=X` request
- [ ] List all uploaded parts for upload ID
- [ ] Support pagination with `part-number-marker`
- [ ] Return XML with part list including ETags
- [ ] Add `s3:ListMultipartUploadParts` IAM action

**Estimated Time:** 4-6 hours

---

### Phase 3: Multipart Upload Completion
**Status:** Not Started

#### 10. CompleteMultipartUpload
- [ ] Parse `POST /key?uploadId=X` with XML body listing parts + ETags
- [ ] Validate all parts are uploaded
- [ ] Verify ETags match
- [ ] Concatenate parts in order to create final object
- [ ] Clean up multipart state and parts
- [ ] Return XML with final object metadata
- [ ] Add `s3:PutObject` IAM action check

#### 11. UploadPartCopy
- [ ] Parse `PUT /key?uploadId=X&partNumber=Y` with `x-amz-copy-source` header
- [ ] Read source object
- [ ] Support `x-amz-copy-source-range` for partial copies
- [ ] Store as part
- [ ] Return XML with part ETag
- [ ] Add source `s3:GetObject` and dest `s3:PutObject` IAM checks

**Estimated Time:** 2-3 hours

---

### Phase 4: Object Tagging
**Status:** Not Started

#### Infrastructure
- [ ] Design tag storage mechanism
  - Option A: Extended attributes (xattr) - platform-dependent
  - Option B: JSON sidecar files (`{key}.tags.json`)
  - Recommendation: JSON sidecar for portability
- [ ] Create tag serialization/deserialization

#### 12. PutObjectTagging
- [ ] Parse `PUT /key?tagging` with XML tag set
- [ ] Validate tag keys/values (AWS limits)
- [ ] Store tags in sidecar file
- [ ] Return 200 OK
- [ ] Add `s3:PutObjectTagging` IAM action

#### 13. GetObjectTagging
- [ ] Parse `GET /key?tagging` request
- [ ] Read tags from storage
- [ ] Return XML tag set
- [ ] Add `s3:GetObjectTagging` IAM action

#### 14. DeleteObjectTagging
- [ ] Parse `DELETE /key?tagging` request
- [ ] Remove tag storage file
- [ ] Return 204 No Content
- [ ] Add `s3:DeleteObjectTagging` IAM action

#### 15. GetObjectAttributes
- [ ] Parse `GET /key?attributes` request with `x-amz-object-attributes` header
- [ ] Return requested attributes (ETag, Checksum, ObjectParts, StorageClass, ObjectSize)
- [ ] Include tags if tag storage exists
- [ ] Add `s3:GetObjectAttributes` IAM action

**Estimated Time:** 2-3 hours

---

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

## Notes

### IAM Actions Reference
New actions to add to `auth.rs::http_method_to_s3_action()`:
- `s3:DeleteObject` (batch)
- `s3:GetObject` (for CopyObject source)
- `s3:GetBucketLocation`
- `s3:ListBucket` (for V1)
- `s3:AbortMultipartUpload`
- `s3:ListBucketMultipartUploads`
- `s3:ListMultipartUploadParts`
- `s3:PutObjectTagging`
- `s3:GetObjectTagging`
- `s3:DeleteObjectTagging`
- `s3:GetObjectAttributes`
- `s3:GetObjectAcl`
- `s3:PutObjectAcl`
- `s3:GetBucketAcl`
- `s3:PutBucketAcl`

### Testing Strategy
- Integration tests for each operation using `aws-sdk-s3`
- Manual testing with `manual_test.sh`
- Policy evaluation tests for new IAM actions
- Ensure `just check` passes after each phase

### Dependencies
May need to add:
- `uuid` crate for multipart upload IDs
- Additional XML serialization structures in `xml_responses.rs`