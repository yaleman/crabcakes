# AWS Signature V4 Integration Plan

## Status: Infrastructure Complete, Integration Pending

### Completed Infrastructure ✅

1. **Dependencies Added**
   - `scratchstack-aws-signature` v0.11.2
   - `scratchstack-aws-principal` v0.4.9
   - `tower` v0.5.2
   - `http` v1.3.1
   - `tempfile` moved to main dependencies

2. **Credential Management**
   - `src/credentials.rs`: CredentialStore for loading JSON credential files
   - Supports directory of JSON files with `access_key_id` and `secret_access_key`
   - CLI flag: `--credentials-dir` (default: `./credentials`)

3. **Signature Verification**
   - `src/auth.rs`: `verify_sigv4()` async function
   - Validates AWS Signature V4 using scratchstack-aws-signature
   - Returns `VerifiedRequest` with authenticated principal
   - CLI flag: `--require-signature` (default: true)

4. **Body Buffering**
   - `src/body_buffer.rs`: Smart buffering with disk spillover
   - Buffers requests <50MB in memory
   - Automatically spills >=50MB requests to temporary files
   - Required because SigV4 needs complete body for signature computation

### Remaining Integration Work 🚧

#### 1. Update S3Handler Structure

**File:** `src/s3_handlers.rs`

**Changes:**
```rust
pub struct S3Handler {
    filesystem: Arc<FilesystemService>,
    policy_store: Arc<PolicyStore>,
    credentials_store: Arc<CredentialStore>,  // NEW
    region: String,                            // NEW
    require_signature: bool,                   // NEW
}
```

**New Method:**
```rust
async fn verify_and_buffer_request(
    &self,
    req: Request<hyper::body::Incoming>,
) -> Result<(VerifiedRequest, BufferedBody, RequestInfo), Response<Full<Bytes>>>
```

This method should:
1. Extract request metadata (method, path, query, headers)
2. Buffer the body using `BufferedBody::from_incoming()`
3. Convert to `http::Request<Vec<u8>>`
4. Call `verify_sigv4()` if `require_signature` is true
5. Return verified request + buffered body OR error response (401)

**Update `handle_request()`:**
- Call `verify_and_buffer_request()` first
- Use buffered body for operations that need it (e.g., PutObject)
- Use verified principal instead of `AuthContext::from_request()`

#### 2. Update Server Initialization

**File:** `src/server.rs`

**Changes:**
```rust
pub struct Server {
    host: String,
    port: u16,
    root_dir: PathBuf,
    policy_dir: PathBuf,
    credentials_dir: PathBuf,   // NEW
    require_signature: bool,     // NEW
}
```

**In `run()` method:**
```rust
// Load credentials
let credentials_store = match CredentialStore::new(self.credentials_dir.clone()) {
    Ok(store) => Arc::new(store),
    Err(e) => {
        error!(error = %e, "Failed to load credentials");
        Arc::new(CredentialStore::new(PathBuf::from("/nonexistent")).unwrap())
    }
};

// Create S3 handler with new parameters
let s3_handler = Arc::new(S3Handler::new(
    filesystem,
    policy_store,
    credentials_store,
    "us-east-1".to_string(), // Or from config
    self.require_signature,
));
```

**In `main.rs`:**
- Parse `credentials_dir` and `require_signature` from CLI
- Pass to `Server::new()`

#### 3. Error Response Handling

**Add to `S3Handler`:**
```rust
fn unauthorized_response(&self, reason: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("Content-Type", "application/xml")
        .body(Full::new(Bytes::from(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>InvalidAccessKeyId</Code>
    <Message>{}</Message>
</Error>"#,
            reason
        ))))
        .unwrap()
}
```

#### 4. Create Test Credentials

**File:** `credentials/alice.json`
```json
{
  "access_key_id": "alice",
  "secret_access_key": "alicesecret123"
}
```

**File:** `credentials/bob.json`
```json
{
  "access_key_id": "bob",
  "secret_access_key": "bobsecret456"
}
```

#### 5. Update Integration Tests

**File:** `src/tests/server_tests.rs`

- Configure AWS SDK to use test credentials
- Set up credential provider with test access keys
- Ensure requests are properly signed
- Test scenarios:
  - Valid signature → success
  - Invalid signature → 401
  - Missing signature (if required) → 401
  - Expired timestamp → 401

**Example:**
```rust
use aws_config::Region;
use aws_sdk_s3::config::Credentials;

let creds = Credentials::new(
    "alice",
    "alicesecret123",
    None,
    None,
    "test"
);

let config = aws_config::defaults(BehaviorVersion::latest())
    .credentials_provider(creds)
    .region(Region::new("us-east-1"))
    .endpoint_url(format!("http://127.0.0.1:{}", port))
    .load()
    .await;
```

#### 6. Update Documentation

**File:** `CLAUDE.md`

Add sections:
- AWS Signature V4 Authentication
  - How signature verification works
  - Credential file format and location
  - Configuration options
- Request Body Buffering
  - Memory vs disk spillover
  - Threshold configuration
- Testing with Signed Requests
  - Using AWS CLI
  - Using AWS SDK

### Implementation Order

1. **Phase 1: Core Integration** (Highest Priority)
   - Update S3Handler structure
   - Implement `verify_and_buffer_request()`
   - Update Server to load credentials
   - Add unauthorized_response()

2. **Phase 2: Testing Infrastructure**
   - Create test credential files
   - Update integration tests
   - Test with AWS CLI manually

3. **Phase 3: Polish**
   - Update CLAUDE.md
   - Add configuration for region
   - Add metrics/logging for auth failures

### Testing Strategy

1. **Unit Tests:**
   - Test BufferedBody with various sizes
   - Test CredentialStore loading
   - Test verify_sigv4() with known signatures

2. **Integration Tests:**
   - Test full request flow with valid signatures
   - Test rejection of invalid signatures
   - Test large file uploads (>50MB)

3. **Manual Testing:**
   - Use AWS CLI with test credentials
   - Test all S3 operations (GET, PUT, HEAD, LIST)
   - Verify error messages are helpful

### Known Challenges

1. **Body Consumption:** Hyper's `Incoming` body can only be consumed once. Need to ensure we don't try to read it twice.

2. **Region Configuration:** Currently hardcoded to "us-east-1". Should be configurable.

3. **Clock Skew:** Need to handle timestamp validation with appropriate tolerance (scratchstack-aws-signature handles this).

4. **Performance:** Body buffering adds overhead. Monitor performance impact, especially for large files.

### Future Enhancements

1. **Credential Rotation:** Watch credential directory for changes
2. **Multiple Regions:** Support per-request region detection
3. **Presigned URLs:** Support pre-signed URL authentication
4. **Anonymous Access:** Configurable per-bucket anonymous read
5. **Credential Caching:** Cache signing key derivations for performance