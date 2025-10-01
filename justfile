check:
    cargo clippy --all-targets --quiet
    cargo test --quiet
    cargo fmt
coverage:
    cargo tarpaulin --out=Html
