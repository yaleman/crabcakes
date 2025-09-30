# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Crabcakes is a simple S3-compatible server written in Rust that serves files from a filesystem directory. The project uses Tokio for async runtime and Hyper for HTTP server functionality.

## Architecture

- `src/main.rs` - Main server entry point with HTTP server setup using Hyper
- `src/cli.rs` - Command-line argument parsing using Clap
- `src/lib.rs` - Library module declarations

The server:
- Binds to a configurable host/port (defaults: 127.0.0.1:8090)
- Uses Tokio for async operations and connection handling
- Currently returns "Hello, World!" for all requests (early development stage)
- CLI accepts `--host`/`--port` flags or `CRABCAKES_HOST`/`CRABCAKES_PORT` environment variables

## Development Commands

### Building and Running
```bash
cargo build                 # Build the project
cargo run                   # Run with default settings (127.0.0.1:8090)
cargo run -- --port 3000    # Run on custom port
cargo run -- --host 0.0.0.0 --port 8080  # Run on all interfaces
```

### Code Quality
```bash
cargo clippy                # Lint the code
cargo fmt                   # Format the code
cargo test                  # Run tests (currently none exist)
```

### Project Analysis
```bash
just check                  # Run comprehensive checks (as per global CLAUDE.md)
```

## Dependencies

Key dependencies:
- `clap` - Command-line argument parsing with derive features
- `hyper` + `hyper-util` - HTTP server implementation
- `tokio` - Async runtime with full features
- `http-body-util` - HTTP body utilities

## Configuration

The server accepts configuration via:
- CLI flags: `--host`, `--port`
- Environment variables: `CRABCAKES_HOST`, `CRABCAKES_PORT`
- Port must be a valid non-zero u16 value
- the tests should copy the 'testfiles/' directory as a base to work from
- the command 'cargo clippy --quiet --all-targets' must pass before you consider your task complete. implement tests using the 'aws-sdk-s3' and 'aws-config' crates to ensure compatibility.