# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Crabcakes is an S3-compatible server written in Rust that serves files from a filesystem directory. The project uses Tokio for async runtime and Hyper for HTTP server functionality.

## Architecture

- `src/main.rs` - Main server entry point with tracing initialization
- `src/cli.rs` - Command-line argument parsing using Clap
- `src/server.rs` - Server struct with HTTP server setup and lifecycle management
- `src/s3_handlers.rs` - S3 API request routing and handler implementations
- `src/web/` - Admin web UI handlers (follows separation of concerns pattern)
  - `src/web/handlers.rs` - HTTP layer (authentication, CSRF, request/response handling)
  - `src/request_handler.rs` - Business logic layer (pure functions, testable without HTTP)
  - `src/web/serde.rs` - Data structures for API requests/responses
  - `src/web/templates.rs` - Askama HTML templates
- `src/filesystem.rs` - Filesystem service for file operations
- `src/xml_responses.rs` - AWS S3-compliant XML response serialization
- `src/auth.rs` - AWS Signature V4 verification and authentication context building
- `src/credentials.rs` - Credential storage and loading from JSON files
- `src/body_buffer.rs` - Smart request body buffering (memory/disk spillover)
- `src/policy.rs` - IAM policy loading and evaluation (with wildcard principal support)
- `src/multipart.rs` - Multipart upload state management
- `src/cleanup.rs` - Background cleanup task for expired PKCE states and credentials
- `src/db/` - Database layer for metadata storage (tags, sessions, credentials, etc.)
  - `src/db/mod.rs` - Database initialization and migration runner
  - `src/db/service.rs` - DBService for metadata, PKCE state, and temp credential operations
  - `src/db/entities/` - SeaORM entity models (object_tags, oauth_pkce_state, temporary_credentials)
- `src/error.rs` - Centralized error handling
- `src/lib.rs` - Library module declarations
- `src/tests/` - Test modules (server_tests.rs, policy_tests.rs, request_handler_tests.rs, web_handlers_tests.rs)

The server:

- Binds to a configurable host/port (defaults: 127.0.0.1:9000)
- Serves files from a configurable root directory (defaults: ./data)
- Loads IAM policies and credentials from a configurable config directory (defaults: ./config)
  - Policies loaded from `config_dir/policies/`
  - Credentials loaded from `config_dir/credentials/`
- Verifies AWS Signature V4 signatures on all requests
- Uses Tokio for async operations and connection handling
- Implements AWS S3-compatible API with XML responses
- Enforces IAM policy-based authorization on all S3 operations
- Smart body buffering: memory for <50MB, disk spillover for ≥50MB
- Stores object metadata (tags, OAuth PKCE state, temporary credentials) in SQLite with SeaORM
- Runs database migrations automatically on startup
- Optional admin UI with OIDC/OAuth2 authentication (configurable via --disable-api)
- CLI accepts `--host`, `--port`, `--root-dir`, `--config-dir`, `--require-signature`, `--disable-api`, `--oidc-client-id`, `--oidc-discovery-url`, `--frontend-url` flags or environment variables
- Uses tracing for structured logging (configure with RUST_LOG environment variable)
- Protected bucket names: admin, api, login, logout, oauth2, .well-known, config, oidc, crabcakes, docs, help

## S3 API Operations

The server implements the following S3 operations:

### Bucket Operations

#### ListBuckets (GET /)

Returns a list of all top-level directories as "buckets"

#### HeadBucket (HEAD /bucket)

Checks if a bucket exists. Returns 200 OK if it exists, 404 Not Found otherwise.

#### CreateBucket (PUT /bucket)

Creates a new bucket (top-level directory). Validates bucket name according to S3 rules:

- 1-63 characters
- Lowercase letters, numbers, and hyphens only
- Cannot start or end with hyphen
Returns 409 Conflict if bucket already exists.

#### DeleteBucket (DELETE /bucket)

Deletes an empty bucket. Returns 409 Conflict with BucketNotEmpty error if the bucket contains objects.

#### GetBucketLocation (GET /bucket?location)

Returns the configured region for the bucket. Region is set via `--region` flag or `CRABCAKES_REGION` env var (default: "crabcakes").

### Object Listing Operations

#### ListObjectsV2 (GET /?list-type=2)

Lists objects with optional prefix filtering and pagination. Supports both:

- Virtual-hosted style: `GET /?list-type=2&prefix=test`
- Path-style: `GET /bucket1/?list-type=2` or `GET /bucket1?prefix=test.txt`

Pagination uses `continuation-token` and `max-keys` parameters.

#### ListObjectsV1 (GET /?prefix= or /?marker=)

Legacy listing API for backward compatibility. Detected when query contains `prefix=`, `marker=`, or `max-keys=` without `list-type=2`.

Pagination uses `marker` parameter instead of `continuation-token`.

### Object Operations

#### HeadObject (HEAD /key)

Returns metadata for an object without the body. Includes:

- Content-Type (detected via mime_guess)
- Content-Length
- ETag (generated from file size and modification time)
- Last-Modified

#### GetObject (GET /key)

Returns the full object content with metadata headers

#### PutObject (PUT /key)

Uploads an object to the specified key

#### CopyObject (PUT /dest-key with x-amz-copy-source header)

Server-side copy of an object. No data transferred through client. Source specified in `x-amz-copy-source` header as `/bucket/key` or `bucket/key`.

#### DeleteObject (DELETE /key)

Deletes an object at the specified key. Returns 204 No Content even if the object doesn't exist (S3 idempotent behavior).

#### DeleteObjects (POST /?delete)

Batch delete multiple objects in a single request. Accepts XML request body with list of keys to delete. Returns XML response with successfully deleted objects and any errors. Supports `quiet` mode to reduce response size.

### Path-Style Request Handling

The server supports AWS CLI path-style requests where the bucket name appears in the URL path:

- `GET /bucket1/test.txt` → retrieves file at `./data/bucket1/test.txt`
- `GET /bucket1?list-type=2&prefix=test.txt` → lists files with prefix `bucket1/test.txt`

### Object Tagging Operations

#### PutObjectTagging (PUT /key?tagging)

Adds or replaces tags on an object. Accepts XML request body with tag set. Tags are stored in SQLite database. Validates:

- Maximum 10 tags per object
- Tag keys: maximum 128 characters
- Tag values: maximum 256 characters

#### GetObjectTagging (GET /key?tagging)

Returns all tags for an object as XML. Returns empty tag set if object has no tags.

#### DeleteObjectTagging (DELETE /key?tagging)

Removes all tags from an object. Returns 204 No Content.

#### GetObjectAttributes (GET /key?attributes)

Returns object metadata including ETag, LastModified, and ObjectSize.

### Bucket Website Configuration

The server supports S3-compatible static website hosting mode. When enabled for a bucket, GET requests automatically serve configured index and error documents.

#### PutBucketWebsite (PUT /bucket?website)

Configures website hosting for a bucket. Accepts XML request body with website configuration:

```xml
<WebsiteConfiguration>
  <IndexDocument>
    <Suffix>index.html</Suffix>
  </IndexDocument>
  <ErrorDocument>
    <Key>error.html</Key>
  </ErrorDocument>
</WebsiteConfiguration>
```

- `IndexDocument.Suffix` - Required. Document to serve for directory requests (e.g., "index.html")
- `ErrorDocument.Key` - Optional. Document to serve for 404 errors (e.g., "error.html")
- Configuration stored in SQLite `bucket_website_configs` table
- Returns 200 OK on success

#### GetBucketWebsite (GET /bucket?website)

Retrieves website configuration for a bucket. Returns:

- 200 OK with XML configuration if website mode enabled
- 404 Not Found with `NoSuchWebsiteConfiguration` error if not configured

#### DeleteBucketWebsite (DELETE /bucket?website)

Removes website configuration from a bucket. Returns 204 No Content on success.

#### Automatic Website Behavior

When website mode is enabled for a bucket:

**Index Document Serving:**

- `GET /bucket/` → serves `/bucket/index.html` (or configured suffix)
- `GET /bucket/subdir/` → serves `/bucket/subdir/index.html`
- Applies to any path ending with `/`
- Falls back to 404 if index document doesn't exist

**Error Document Serving:**

- 404 errors automatically serve configured error document
- Error document served with 404 status code
- Includes proper Content-Type and Content-Length headers
- Falls back to standard XML error if error document not found or not configured

**Website Mode Detection:**

- Server checks `bucket_website_configs` table for each request
- Configuration cached during request processing
- No performance impact when website mode disabled

## Metadata Storage

The server uses SQLite for storing object metadata, OAuth PKCE state, temporary credentials, and bucket website configurations.

### Database Overview

- Database file: `{config_dir}/crabcakes.sqlite3` (default: `./config/crabcakes.sqlite3`)
- Automatically created on first startup
- Migrations run automatically on startup using SeaORM migration framework
- Sessions managed by tower-sessions (auto-creates its own table)

**For complete database schema, ERD diagrams, and migration details, see [docs/src/database.md](docs/src/database.md)**

### Key Database Tables

- `object_tags` - S3 object tags storage with validation
- `bucket_website_configs` - Static website hosting configuration per bucket
- `oauth_pkce_state` - OAuth PKCE flow state (temporary)
- `temporary_credentials` - AWS-style temporary credentials for web UI users
- `tower_sessions` - Session storage (auto-managed by tower-sessions)

### DBService Operations

The `DBService` struct (`src/db/service.rs`) provides database operations for:

- **Tag Operations** - put_tags, get_tags, delete_tags
- **Bucket Website Configuration** - put_website_config, get_website_config, delete_website_config
- **OAuth PKCE State** - store_pkce_state, get_pkce_state, delete_pkce_state, cleanup_expired_pkce_states
- **Temporary Credentials** - store_temporary_credentials, get_temporary_credentials, delete_temporary_credentials, cleanup_expired_credentials

**See [docs/src/database.md](docs/src/database.md) for complete API signatures and details.**

### Background Cleanup

A background task (`src/cleanup.rs`) runs every 5 minutes to automatically remove expired OAuth PKCE states and temporary credentials, preventing database bloat.

## AWS Signature V4 Authentication

The server implements full AWS Signature V4 (SigV4) authentication for production-ready request signing:

### Credential Management

The server supports two types of AWS credentials:

**Permanent Credentials** (for S3 operations):

- Stored in JSON files in `config_dir/credentials/` (default: `./config/credentials/`)
- Each credential file contains:

  ```json
  {
    "access_key_id": "alice",
    "secret_access_key": "alicesecret123"
  }
  ```

- CredentialStore loads all JSON files at startup
- Credentials mapped by access_key_id for fast lookup during signature verification

**Temporary Credentials** (for admin UI users):

- Generated on successful OIDC login
- Stored in SQLite `temporary_credentials` table
- Linked to user session via `session_id`
- Automatically expired and cleaned up
- Returned to web UI for client-side S3 operations

### Signature Verification Flow

1. **Request Buffering**: Body is buffered before verification
   - Small requests (<50MB) buffered in memory
   - Large requests (≥50MB) automatically spill to disk (uses `tempfile` crate)
   - Necessary because SigV4 requires complete body for signature computation
2. **Signature Verification**: Using `scratchstack-aws-signature` crate
   - Extracts Authorization header
   - Parses access_key_id from Credential field
   - Looks up secret_access_key from CredentialStore
   - Derives signing key from secret + date + region + service
   - Computes signature and compares with request signature
3. **Principal Extraction**: Extracts authenticated user from verified request
4. **Policy Evaluation**: Uses authenticated principal for IAM authorization

### Configuration

- `--config-dir <path>` or `CRABCAKES_CONFIG_DIR`: Base configuration directory (default: `./config`)
  - Policies loaded from `config_dir/policies/`
  - Credentials loaded from `config_dir/credentials/`
- `--region <name>` or `CRABCAKES_REGION`: AWS region name (default: `crabcakes`)
- `--oidc-client-id <id>` or `CRABCAKES_OIDC_CLIENT_ID`: OAuth client ID (required if API enabled)
- `--oidc-discovery-url <url>` or `CRABCAKES_OIDC_DISCOVERY_URL`: OIDC discovery URL (required if API enabled)
- `--frontend-url <url>` or `CRABCAKES_FRONTEND_URL`: Frontend URL for OIDC redirect URIs when behind a reverse proxy (e.g., `https://example.com`). If not set, uses `http(s)://hostname:port`

### Test Mode

- Allows integration tests to run without signing requests
- Uses wildcard principal with allow-all policy for authorization

### Request Body Buffering

The `BufferedBody` enum handles smart body buffering:

- **Memory variant**: Holds `Vec<u8>` for small requests
- **Disk variant**: Holds `NamedTempFile` and size for large requests
- **Threshold**: 50MB (configurable via `MEMORY_THRESHOLD` constant)
- **Auto-cleanup**: Temp files automatically deleted when BufferedBody is dropped
- **Async I/O**: Uses tokio for async file operations

### Security Considerations

- Test credentials in `test_config/credentials/` directory are for testing only
- Production credentials should never be committed to git (add `config/` to `.gitignore`)
- Signature verification ensures request integrity and authenticity
- Time-based signature expiration handled by scratchstack-aws-signature

## IAM Authorization

The server implements AWS IAM-compatible policy-based authorization:

### Authentication Context

After signature verification (or if signatures not required), authentication context is built:

- **Authenticated requests**: Principal set to `arn:aws:iam:::user/{username}` from verified access_key_id
- **Anonymous requests**: Principal set to `Principal::Wildcard` (requires policy with `"Principal": "*"`)

### Authorization Flow

1. Extract authentication context from request
2. Determine S3 action from HTTP method and path (e.g., `s3:GetObject`, `s3:PutObject`, `s3:ListBucket`)
3. Extract bucket and key from request path
4. Build IAM request with principal, action, resource ARN, and context
5. Evaluate request against all loaded policies
6. Return 403 Forbidden if denied, proceed if allowed

### Policy Evaluation

- Follows AWS IAM evaluation logic:
  - Default deny
  - Explicit deny wins over allow
  - At least one allow is needed
- Loads all JSON policy files from `config_dir/policies/` at startup
- Caches policy evaluation results using SHA256 hashing for performance
- Supports standard IAM policy syntax with:
  - Principal matching (AWS ARNs, wildcards)
  - Action matching (S3 actions with wildcards)
  - Resource matching (S3 ARNs with wildcards)
  - Context-based conditions (e.g., `${aws:username}` variable interpolation)

### Policy Examples

See `test_config/policies/` directory for examples:

- `testuser.json` - Allows the test user access to things for tests

## Development Commands

### Building and Running

```bash
cargo build --quiet                                     # Build the project
cargo run --quiet                                       # Run with defaults (127.0.0.1:9000, ./data, ./config)
cargo run --quiet -- --port 3000                        # Run on custom port
cargo run --quiet -- --host 0.0.0.0 --port 8080         # Run on all interfaces
cargo run --quiet -- --root-dir /path/to/data           # Serve from custom directory
cargo run --quiet -- --config-dir /path/to/config       # Load policies and credentials from custom directory
cargo run --quiet -- --require-signature false          # Disable signature verification (testing only)
cargo run --quiet -- --region us-east-1                 # Set region (default: crabcakes)
cargo run --quiet -- --disable-api                      # Disable admin UI
RUST_LOG=debug cargo run --quiet                        # Run with debug logging
```

### Testing

```bash
cargo test                              # Run all tests
cargo test --lib                        # Run unit tests
bash manual_test.sh                     # Run manual AWS CLI tests
```

The project includes:

- 5 unit tests in `src/filesystem.rs`
- Unit tests in `src/auth.rs` for authentication parsing and resource extraction
- 33 integration tests in `src/tests/server_tests.rs`
- Policy evaluation tests in `src/tests/policy_tests.rs`
- Manual test script using AWS CLI

### Building JavaScript

The project bundles AWS SDK v3 for local hosting (no CDN dependencies):

```bash
pnpm run build                          # Build JavaScript bundles (AWS SDK)
just build-js                           # Same as above
```

**Build process:**

- Source: `static/js/bucket-operations-src.js` (imports from `@aws-sdk/client-s3`)
- Output: `static/js/bucket-operations.js` (bundled, minified, ~217KB)
- Tool: esbuild (configured in `build-aws-sdk.js`)
- The bundled file is git-ignored and must be built before deployment

### Code Quality

```bash
cargo clippy --all-targets --quiet      # Lint Rust code (must pass with no warnings)
cargo fmt                               # Format Rust code
pnpm run lint                           # Lint JavaScript and CSS
pnpm run lint:css                       # Lint CSS only
just check                              # Run comprehensive checks (Rust + JS/CSS)
just lint-web                           # Lint JavaScript and CSS only
```

The project uses:

- **ESLint** for JavaScript linting (configured in `.eslintrc.json`)
  - Bundled files (`bucket-operations.js`) are excluded from linting
- **Stylelint** for CSS linting (configured in `.stylelintrc.json`)
- **pnpm** for Node.js package management (never use npm)
- **esbuild** for bundling JavaScript with dependencies
- Third-party CSS files like `prism.css` are excluded from linting

## Dependencies

Key dependencies:

- `clap` - Command-line argument parsing with derive features
- `hyper` + `hyper-util` - HTTP server implementation
- `tokio` - Async runtime with full features
- `http-body-util` - HTTP body utilities
- `tracing` + `tracing-subscriber` - Structured logging
- `chrono` - Date/time handling for S3 timestamps
- `mime_guess` - Content-Type detection
- `quick-xml` + `serde` - XML serialization for S3 responses
- `iam-rs` - IAM policy evaluation (local path dependency)
- `serde_json` - JSON parsing for policy and credential files
- `sha2` - SHA256 hashing for policy evaluation cache
- `scratchstack-aws-signature` - AWS Signature V4 verification
- `scratchstack-aws-principal` - AWS principal types for signature verification
- `tower` - Service trait for signature verification
- `http` - HTTP types for signature verification
- `tempfile` - Temporary files for large request body spillover
- `sea-orm` + `sea-orm-migration` - ORM and migrations for SQLite
- `tower-sessions` - Session management middleware
- `tower-sessions-sqlx-store` - SQLite session store
- `openidconnect` - OIDC/OAuth2 client with PKCE support
- `rand` - Random generation for credentials and PKCE

Dev dependencies:

- `aws-sdk-s3` + `aws-config` - AWS CLI compatibility testing
- `reqwest` - HTTP client for integration tests

## Runtime Configuration

The server accepts configuration via:

- CLI flags: `--host`, `--port`, `--root-dir`, `--config-dir`, `--require-signature`, `--region`, `--disable-api`, `--oidc-client-id`, `--oidc-discovery-url`, `--frontend-url`
- Environment variables: `CRABCAKES_LISTENER_ADDRESS`, `CRABCAKES_PORT`, `CRABCAKES_ROOT_DIR`, `CRABCAKES_CONFIG_DIR`, `CRABCAKES_REGION`, `CRABCAKES_OIDC_CLIENT_ID`, `CRABCAKES_OIDC_DISCOVERY_URL`, `CRABCAKES_FRONTEND_URL`, `CRABCAKES_TLS_CERT`,`CRABCAKES_TLS_KEY`
- Port must be a valid non-zero u16 value
- Root directory defaults to `./data` and must exist
- Config directory defaults to `./config` (if it doesn't exist, server starts with no policies/credentials)
  - Policies loaded from `config_dir/policies/`
  - Credentials loaded from `config_dir/credentials/`
  - SQLite database at `config_dir/crabcakes.sqlite3`
- Region defaults to `"crabcakes"` and is returned by GetBucketLocation
- Admin UI enabled by default (set `--disable-api` to disable)
- Reserved bucket names cannot be created: admin, api, login, logout, oauth2, .well-known, config, oidc, crabcakes, docs, help

## Testing Guidelines

- Tests copy files from `testfiles/` directory as a base to work from
- Integration tests use `Server::test_mode()` to find random available ports
- Test mode uses `test_config/` as the base config directory
  - Policies loaded from `test_config/policies/`
  - Credentials loaded from `test_config/credentials/`
- The command `cargo clippy --quiet --all-targets` must pass with no warnings
- Tests use `aws-sdk-s3` and `aws-config` crates to ensure AWS CLI compatibility
- Manual test script validates real-world AWS CLI usage
- Policy evaluation tests verify IAM policy logic with different principals and resources
- All new features require test coverage for: signed/unsigned requests, success/failure cases
- Integration tests must be added to `manual_test.sh` for signed request validation
- all tests that might involve the database should be against an in-memory database where possible, or if it's testing disk functionality then the config dir should be a temporary directory for that test
- Ensure CLAUDE.md is kept up to date with the current design

## Web Handler Architecture Pattern

The admin UI follows a **separation of concerns pattern** with distinct layers:

### Layer Structure

**WebHandler** (`src/web/handlers.rs`):

- HTTP layer responsibilities only
- Authentication checking (session validation)
- CSRF token validation
- Request parsing (headers, body, query parameters)
- Response building (JSON, HTML with security headers)
- Calls RequestHandler for business logic

**RequestHandler** (`src/request_handler.rs`):

- Pure business logic functions
- No HTTP dependencies (no Request/Response types)
- No authentication/CSRF concerns (already validated)
- Testable with simple unit tests
- Returns Result types for error handling

**Data Structures** (`src/web/serde.rs`):

- Request/response types for API endpoints
- Separate from HTTP layer
- Used by both WebHandler and RequestHandler

### Pattern Example

```rust
// WebHandler - HTTP concerns
async fn post_api_bucket(&self, req: Request<Incoming>, session: Session) -> Result<Response<Full<Bytes>>, CrabCakesError> {
    // 1. Check authentication
    self.check_auth(&session).await?;

    // 2. Parse request
    let (parts, body) = req.into_parts();

    // 3. Validate CSRF
    self.validate_csrf_token(&session, &parts.headers).await?;

    // 4. Parse body
    let body_bytes = body.collect().await?.to_bytes();
    let request: CreateBucketRequest = serde_json::from_str(std::str::from_utf8(&body_bytes)?)?;

    // 5. Call business logic
    self.request_handler.api_create_bucket(&request.bucket_name).await?;

    // 6. Build response
    self.build_json_response(json!({"success": true, "bucket_name": request.bucket_name}))
}

// RequestHandler - Business logic
pub(crate) async fn api_create_bucket(&self, bucket_name: &str) -> Result<(), CrabCakesError> {
    // Pure business logic - delegates to services
    self.filesystem.create_bucket(bucket_name).await.map_err(CrabCakesError::from)
}
```

### Guidelines for New Handlers

**ALWAYS follow this pattern when adding new API endpoints:**

1. **WebHandler method** handles HTTP layer:
   - Check authentication with `self.check_auth(&session).await?`
   - Validate CSRF with `self.validate_csrf_token(&session, &parts.headers).await?`
   - Parse request body/parameters
   - Call RequestHandler method for business logic
   - Build and return HTTP response

2. **RequestHandler method** contains business logic:
   - Takes simple Rust types as parameters (not HTTP types)
   - Returns `Result<T, CrabCakesError>`
   - Delegates to service layers (filesystem, db, policy_store, etc.)
   - No knowledge of HTTP, sessions, or CSRF

3. **Unit tests** in `src/tests/request_handler_tests.rs`:
   - Test RequestHandler methods directly
   - Use `RequestHandler::new_test()` for test setup
   - No HTTP mocking required
   - Test both success and error cases
   - Verify validation rules and edge cases

4. **Integration tests** (if needed) in `src/tests/web_handlers_tests.rs`:
   - Test full HTTP flow including authentication
   - Use actual HTTP requests with sessions
   - Verify CSRF protection works

### Benefits

- **Testability**: Business logic tested without HTTP complexity
- **Separation**: HTTP concerns isolated from business rules
- **Maintainability**: Clear boundaries between layers
- **Reusability**: Business logic can be called from multiple handlers
- **Security**: Authentication/CSRF enforced at HTTP layer, not scattered

### Constructor Pattern

**Production use:**

```rust
let request_handler = RequestHandler::new(db, credentials_store, policy_store, filesystem);
```

**Test use:**

```rust
let request_handler = RequestHandler::new_test().await;
// Automatically sets up in-memory DB, temp directories, test policies
```

## UI Design

The admin web UI uses a purple gradient theme (`#667eea` to `#764ba2`):

- Background: Purple gradient (135deg)
- Primary elements: Purple gradient accents with transparency
- Info section: Light purple gradient background with purple borders
- Labels: Purple color (#5a67d8)
- Status badge: Green (#28a745) when authenticated
- Sign out button: Red (#dc3545) background with hover effects
- Maintain cohesive purple vibe throughout all UI elements
- never use npm, use pnpm instead
- always use static files for css/js, it is NEVER acceptable for such code to be inline
- don't use javascript alerts to show things worked, redirect to the resulting object with a notification message

## generic guidelines

- don't mention how many tests there are, anywhere. nobody cares.
- users should refer to documentation over CLAUDE.md as documentation is for humans, and CLAUDE is for a tool.
- TODO.md is not for documentation, remove completed tasks entirely from it when done
- NEVER use inline CSS or javascript.
- never look at the javascript files in `static/js/` unless troubleshooting their build phase - they are built from the typescript in `src/js/`