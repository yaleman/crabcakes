# Crabcakes S3 API Implementation TODO

## Currently Implemented Operations (24)
### Core Operations
- ✅ ListBuckets
- ✅ ListObjectsV2
- ✅ ListObjectsV1 (legacy)
- ✅ HeadBucket
- ✅ CreateBucket
- ✅ DeleteBucket
- ✅ GetBucketLocation
- ✅ GetObject
- ✅ HeadObject
- ✅ PutObject
- ✅ DeleteObject
- ✅ DeleteObjects (batch)
- ✅ CopyObject

### Multipart Upload Operations
- ✅ CreateMultipartUpload
- ✅ UploadPart
- ✅ UploadPartCopy
- ✅ CompleteMultipartUpload
- ✅ AbortMultipartUpload
- ✅ ListMultipartUploads
- ✅ ListParts

### Object Tagging Operations
- ✅ PutObjectTagging
- ✅ GetObjectTagging
- ✅ DeleteObjectTagging
- ✅ GetObjectAttributes

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
**Status:** ✅ Complete

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
**Status:** ✅ Complete

#### Infrastructure
- [x] Design multipart upload state storage
  - Filesystem directory structure (persistent)
  - Implementation: `{root}/.multipart/{bucket}/{uploadId}/`
- [x] Generate unique upload IDs (UUID)
- [x] Store upload metadata (bucket, key, initiated time)

#### 5. CreateMultipartUpload
- [x] Parse `POST /key?uploads` request
- [x] Generate upload ID
- [x] Create multipart state directory
- [x] Return XML with `<UploadId>`
- [x] Add `s3:PutObject` IAM action check

#### 6. UploadPart
- [x] Parse `PUT /key?uploadId=X&partNumber=Y` request
- [x] Validate part number (1-10000)
- [x] Store part data with ETag
- [x] Return ETag header
- [x] Add `s3:PutObject` IAM action check

#### 7. AbortMultipartUpload
- [x] Parse `DELETE /key?uploadId=X` request
- [x] Clean up all uploaded parts
- [x] Remove multipart state
- [x] Return 204 No Content
- [x] Add `s3:AbortMultipartUpload` IAM action

#### 8. ListMultipartUploads
- [x] Parse `GET /bucket?uploads` request
- [x] List all active uploads in bucket
- [x] Return XML with upload list
- [x] Add `s3:ListBucketMultipartUploads` IAM action

#### 9. ListParts
- [x] Parse `GET /key?uploadId=X` request
- [x] List all uploaded parts for upload ID
- [x] Return XML with part list including ETags
- [x] Add `s3:ListMultipartUploadParts` IAM action

**Completed:** All multipart infrastructure and handlers implemented with manual tests

---

### Phase 3: Multipart Upload Completion
**Status:** ✅ Complete

#### 10. CompleteMultipartUpload
- [x] Parse `POST /key?uploadId=X` with XML body listing parts + ETags
- [x] Validate all parts are uploaded
- [x] Verify ETags match
- [x] Concatenate parts in order to create final object
- [x] Clean up multipart state and parts
- [x] Return XML with final object metadata
- [x] Add `s3:PutObject` IAM action check

**Status:** ✅ Complete

#### 11. UploadPartCopy
- [x] Parse `PUT /key?uploadId=X&partNumber=Y` with `x-amz-copy-source` header
- [x] Read source object
- [x] Support `x-amz-copy-source-range` for partial copies
- [x] Store as part
- [x] Return ETag header
- [x] Add source `s3:GetObject` and dest `s3:PutObject` IAM checks

**Status:** ✅ Complete

---

### Phase 4: Object Tagging
**Status:** ✅ Complete

#### Infrastructure
- [x] Design tag storage mechanism - SQLite database with SeaORM
- [x] Create database migration framework using sea-orm-migration
- [x] Implement DBService for tag operations
- [x] Create object_tags table with proper indexes

#### 12. PutObjectTagging
- [x] Parse `PUT /key?tagging` with XML tag set
- [x] Validate tag keys/values (AWS limits: max 10 tags, 128 char key, 256 char value)
- [x] Store tags in SQLite database
- [x] Return 200 OK
- [x] Add `s3:PutObjectTagging` IAM action

#### 13. GetObjectTagging
- [x] Parse `GET /key?tagging` request
- [x] Read tags from database
- [x] Return XML tag set
- [x] Add `s3:GetObjectTagging` IAM action

#### 14. DeleteObjectTagging
- [x] Parse `DELETE /key?tagging` request
- [x] Remove tags from database
- [x] Return 204 No Content
- [x] Add `s3:DeleteObjectTagging` IAM action

#### 15. GetObjectAttributes
- [x] Parse `GET /key?attributes` request
- [x] Return object attributes (ETag, LastModified, ObjectSize)
- [x] Add `s3:GetObjectAttributes` IAM action

**Completed:** All tagging operations implemented with SQLite storage, migrations, and manual tests

**Database Details:**
- Location: `{config_dir}/crabcakes.sqlite3`
- Migration system: SeaORM migrations run automatically on startup
- Schema: `object_tags` table with unique constraint on (bucket, key, tag_key)
- Service: `DBService` provides tag CRUD operations with validation

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