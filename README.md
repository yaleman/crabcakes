# crabcakes

A lightweight S3-compatible server that serves files from your filesystem.

## Features

- S3 API compatibility (ListBuckets, ListObjectsV2, HeadObject, GetObject)
- Path-style and virtual-hosted style requests
- Structured logging with tracing
- Works with AWS CLI and SDKs

## Quick Start

```bash
# Start server (default: http://127.0.0.1:8090, serving ./data)
cargo run --quiet

# Custom configuration
cargo run --quiet -- --host 0.0.0.0 --port 8080 --root-dir /path/to/files

# With debug logging
RUST_LOG=debug cargo run --quiet
```

## Usage with AWS CLI

```bash
# List buckets
aws s3 ls --endpoint-url http://127.0.0.1:8090

# List objects in a bucket
aws s3 ls s3://bucket1/ --endpoint-url http://127.0.0.1:8090

# Get object metadata
aws s3api head-object --bucket bucket1 --key test.txt --endpoint-url http://127.0.0.1:8090

# Download object
aws s3 cp s3://bucket1/test.txt . --endpoint-url http://127.0.0.1:8090
```

## Testing

```bash
cargo test                  # Run all tests
bash manual_test.sh         # Test with AWS CLI
```
