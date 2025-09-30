check:
    cargo clippy --all-targets --quiet
    cargo test --quiet
    cargo fmt
