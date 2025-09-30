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
- `src/auth.rs` - Authentication context extraction and IAM request building
- `src/policy.rs` - IAM policy loading and evaluation
- `src/error.rs` - Centralized error handling
- `src/lib.rs` - Library module declarations
- `src/tests/` - Test modules (server_tests.rs, policy_tests.rs)

The server:

- Binds to a configurable host/port (defaults: 127.0.0.1:8090)
- Serves files from a configurable root directory (defaults: ./data)
- Loads IAM policies from a configurable policy directory (defaults: ./policies)
- Uses Tokio for async operations and connection handling
- Implements AWS S3-compatible API with XML responses
- Enforces IAM policy-based authorization on all S3 operations
- CLI accepts `--host`, `--port`, `--root-dir`, and `--policy-dir` flags or environment variables
- Uses tracing for structured logging (configure with RUST_LOG environment variable)

## S3 API Operations

The server implements the following S3 operations:

### ListBuckets (GET /)
Returns a list of all top-level directories as "buckets"

### ListObjectsV2 (GET /?list-type=2)
Lists objects with optional prefix filtering and pagination. Supports both:
- Virtual-hosted style: `GET /?list-type=2&prefix=test`
- Path-style: `GET /bucket1/?list-type=2` or `GET /bucket1?prefix=test.txt`

### HeadObject (HEAD /key)
Returns metadata for an object without the body. Includes:
- Content-Type (detected via mime_guess)
- Content-Length
- ETag (generated from file size and modification time)
- Last-Modified

### GetObject (GET /key)
Returns the full object content with metadata headers

### PutObject (PUT /key)
Uploads an object to the specified key

### Path-Style Request Handling
The server supports AWS CLI path-style requests where the bucket name appears in the URL path:
- `GET /bucket1/test.txt` → retrieves file at `./data/bucket1/test.txt`
- `GET /bucket1?list-type=2&prefix=test.txt` → lists files with prefix `bucket1/test.txt`

## IAM Authorization

The server implements AWS IAM-compatible policy-based authorization:

### Authentication
- Extracts authentication from request headers:
  - `x-amz-user` header (simplified for testing)
  - `Authorization` header (AWS Signature V4 format - access key extraction)
- Falls back to anonymous/wildcard principal if no auth found

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
- Loads all JSON policy files from `--policy-dir` at startup
- Caches policy evaluation results using SHA256 hashing for performance
- Supports standard IAM policy syntax with:
  - Principal matching (AWS ARNs, wildcards)
  - Action matching (S3 actions with wildcards)
  - Resource matching (S3 ARNs with wildcards)
  - Context-based conditions (e.g., `${aws:username}` variable interpolation)

### Policy Examples
See `test_policies/` directory for examples:
- `allow-all.json` - Allows all S3 operations for all principals
- `alice.json` - Allows Alice to access only her own prefix (`/bucket/alice/*`)

## Development Commands

### Building and Running

```bash
cargo build --quiet                                     # Build the project
cargo run --quiet                                       # Run with defaults (127.0.0.1:8090, ./data, ./policies)
cargo run --quiet -- --port 3000                        # Run on custom port
cargo run --quiet -- --host 0.0.0.0 --port 8080         # Run on all interfaces
cargo run --quiet -- --root-dir /path/to/data           # Serve from custom directory
cargo run --quiet -- --policy-dir /path/to/policies     # Load policies from custom directory
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
- 9 integration tests in `src/tests/server_tests.rs`
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
- `serde_json` - JSON parsing for policy files
- `sha2` - SHA256 hashing for policy evaluation cache

Dev dependencies:
- `aws-sdk-s3` + `aws-config` - AWS CLI compatibility testing
- `reqwest` - HTTP client for integration tests
- `tempfile` - Temporary directories for test isolation

## Configuration

The server accepts configuration via:
- CLI flags: `--host`, `--port`, `--root-dir`, `--policy-dir`
- Environment variables: `CRABCAKES_HOST`, `CRABCAKES_PORT`, `CRABCAKES_ROOT_DIR`, `CRABCAKES_POLICY_DIR`
- Port must be a valid non-zero u16 value
- Root directory defaults to `./data` and must exist
- Policy directory defaults to `./policies` (if it doesn't exist, server starts with no policies)

## Testing Guidelines

- Tests copy files from `testfiles/` directory as a base to work from
- Integration tests use `Server::test_mode()` to find random available ports
- Test mode uses `test_policies/` directory for policy files
- The command `cargo clippy --quiet --all-targets` must pass with no warnings
- Tests use `aws-sdk-s3` and `aws-config` crates to ensure AWS CLI compatibility
- Manual test script validates real-world AWS CLI usage
- Policy evaluation tests verify IAM policy logic with different principals and resources
