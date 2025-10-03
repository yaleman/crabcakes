# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Crabcakes is an S3-compatible server written in Rust that serves files from a filesystem directory. The project uses Tokio for async runtime and Hyper for HTTP server functionality.

## Architecture

- `src/main.rs` - Main server entry point with tracing initialization
- `src/cli.rs` - Command-line argument parsing using Clap
- `src/server.rs` - Server struct with HTTP server setup and lifecycle management
- `src/s3_handlers.rs` - S3 API request routing and handler implementations
- `src/filesystem.rs` - Filesystem service for file operations
- `src/xml_responses.rs` - AWS S3-compliant XML response serialization
- `src/auth.rs` - AWS Signature V4 verification and authentication context building
- `src/credentials.rs` - Credential storage and loading from JSON files
- `src/body_buffer.rs` - Smart request body buffering (memory/disk spillover)
- `src/policy.rs` - IAM policy loading and evaluation (with wildcard principal support)
- `src/multipart.rs` - Multipart upload state management
- `src/db/` - Database layer for metadata storage (tags, attributes, etc.)
  - `src/db/mod.rs` - Database initialization and migration runner
  - `src/db/service.rs` - DBService for metadata operations
  - `src/db/entities/` - SeaORM entity models
  - `src/db/migration/` - Database migrations
- `src/error.rs` - Centralized error handling
- `src/lib.rs` - Library module declarations
- `src/tests/` - Test modules (server_tests.rs, policy_tests.rs)

The server:

- Binds to a configurable host/port (defaults: 127.0.0.1:8090)
- Serves files from a configurable root directory (defaults: ./data)
- Loads IAM policies and credentials from a configurable config directory (defaults: ./config)
  - Policies loaded from `config_dir/policies/`
  - Credentials loaded from `config_dir/credentials/`
  - SQLite database at `config_dir/crabcakes.sqlite3` for metadata storage
- Verifies AWS Signature V4 signatures on all requests (configurable via --require-signature)
- Uses Tokio for async operations and connection handling
- Implements AWS S3-compatible API with XML responses
- Enforces IAM policy-based authorization on all S3 operations
- Smart body buffering: memory for <50MB, disk spillover for ≥50MB
- Stores object metadata (tags) in SQLite with SeaORM
- Runs database migrations automatically on startup
- CLI accepts `--host`, `--port`, `--root-dir`, `--config-dir`, and `--require-signature` flags or environment variables
- Uses tracing for structured logging (configure with RUST_LOG environment variable)

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

## Metadata Storage

The server uses SQLite for storing object metadata (tags, future: ACLs, object attributes).

### Database Location

- Database file: `{config_dir}/crabcakes.sqlite3` (default: `./config/crabcakes.sqlite3`)
- Automatically created on first startup
- Migrations run automatically on startup using SeaORM migration framework

### Schema

**`object_tags` table:**
- `id` INTEGER PRIMARY KEY
- `bucket` TEXT NOT NULL
- `key` TEXT NOT NULL
- `tag_key` TEXT NOT NULL
- `tag_value` TEXT NOT NULL
- `created_at` DATETIME NOT NULL
- Unique index on `(bucket, key, tag_key)`
- Lookup index on `(bucket, key)`

### Migrations

New database migrations should be added to `src/db/migration/`:
1. Create new migration file: `src/db/migration/mYYYYMMDD_HHMMSS_description.rs`
2. Implement `up()` and `down()` methods using SeaORM schema builder
3. Add to migration list in `src/db/migration/mod.rs`
4. Migrations run automatically on server startup

### DBService

The `DBService` struct in `src/db/service.rs` provides tag operations:
- `put_tags(bucket, key, tags)` - Store/replace tags with validation
- `get_tags(bucket, key)` - Retrieve all tags for an object
- `delete_tags(bucket, key)` - Remove all tags for an object

Future metadata operations (ACLs, object attributes) will be added to DBService.

## AWS Signature V4 Authentication

The server implements full AWS Signature V4 (SigV4) authentication for production-ready request signing:

### Credential Management

- Credentials stored in JSON files in `config_dir/credentials/` (default: `./config/credentials/`)
- Each credential file contains:
  ```json
  {
    "access_key_id": "alice",
    "secret_access_key": "alicesecret123"
  }
  ```
- CredentialStore loads all JSON files at startup
- Credentials mapped by access_key_id for fast lookup during signature verification

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
- `--require-signature <bool>` or `CRABCAKES_REQUIRE_SIGNATURE`: Whether to require signature verification (default: `true`)
- `--region <name>` or `CRABCAKES_REGION`: AWS region name (default: `crabcakes`)

### Test Mode

- `Server::test_mode()` disables signature verification (`require_signature=false`)
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
- `allow-all.json` - Allows all S3 operations for all principals
- `alice.json` - Allows Alice to access only her own prefix (`/bucket/alice/*`)

## Development Commands

### Building and Running

```bash
cargo build --quiet                                     # Build the project
cargo run --quiet                                       # Run with defaults (127.0.0.1:8090, ./data, ./config, require_signature=true)
cargo run --quiet -- --port 3000                        # Run on custom port
cargo run --quiet -- --host 0.0.0.0 --port 8080         # Run on all interfaces
cargo run --quiet -- --root-dir /path/to/data           # Serve from custom directory
cargo run --quiet -- --config-dir /path/to/config       # Load policies and credentials from custom directory
cargo run --quiet -- --require-signature false          # Disable signature verification (testing only)
cargo run --quiet -- --region foobar                 # Set region (default: crabcakes)
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

### Code Quality

```bash
cargo clippy --all-targets --quiet      # Lint the code (must pass with no warnings)
cargo fmt                               # Format the code
just check                              # Run comprehensive checks
```

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

Dev dependencies:
- `aws-sdk-s3` + `aws-config` - AWS CLI compatibility testing
- `reqwest` - HTTP client for integration tests

## Configuration

The server accepts configuration via:
- CLI flags: `--host`, `--port`, `--root-dir`, `--config-dir`, `--require-signature`, `--region`
- Environment variables: `CRABCAKES_HOST`, `CRABCAKES_PORT`, `CRABCAKES_ROOT_DIR`, `CRABCAKES_CONFIG_DIR`, `CRABCAKES_REQUIRE_SIGNATURE`, `CRABCAKES_REGION`
- Port must be a valid non-zero u16 value
- Root directory defaults to `./data` and must exist
- Config directory defaults to `./config` (if it doesn't exist, server starts with no policies/credentials)
  - Policies loaded from `config_dir/policies/`
  - Credentials loaded from `config_dir/credentials/`
- Signature verification defaults to `true` (set to `false` to disable)
- Region defaults to `"crabcakes"` and is returned by GetBucketLocation

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