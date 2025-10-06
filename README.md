# crabcakes

A lightweight S3-compatible server that serves files from your filesystem.

## Features

- S3-compatible API
- AWS Signature V4 authentication with IAM policy-based authorization
- Path-style and virtual-hosted style requests
- Streaming uploads with AWS chunked encoding support
- Smart body buffering (memory/disk spillover)
- Works with AWS CLI and SDKs

## Quick Start

If you're working in the repository, build the binary:

```bash
cargo build --release
```

Or install it with `cargo install crabcakes` (or use the docker container `ghcr.io/yaleman/crabcakes:latest`)

```bash
# Start server (default: http://localhost:9000, serving ./data)
crabcakes

# Custom configuration
crabcakes --host 0.0.0.0 --port 8080 --root-dir /path/to/files

# With debug logging
RUST_LOG=debug crabcakes
```

## Usage with AWS CLI

```bash
# List buckets
aws s3 ls --endpoint-url http://localhost:9000

# Create bucket
aws s3 mb s3://mybucket --endpoint-url http://localhost:9000

# Upload object
aws s3 cp file.txt s3://mybucket/ --endpoint-url http://localhost:9000

# Download object
aws s3 cp s3://mybucket/file.txt . --endpoint-url http://localhost:9000

# Delete multiple objects
aws s3api delete-objects --bucket mybucket --delete '{"Objects":[{"Key":"file1.txt"},{"Key":"file2.txt"}]}' --endpoint-url http://localhost:9000

# Copy object (server-side)
aws s3api copy-object --bucket mybucket --key dest.txt --copy-source mybucket/source.txt --endpoint-url http://localhost:9000
```

## Testing

```bash
cargo test       # Run all tests
./manual_test.sh # Test with AWS CLI, tends to find weirdness
```

## Credits

- Syntax highlighting powered by [Prism.js](https://prismjs.com)
