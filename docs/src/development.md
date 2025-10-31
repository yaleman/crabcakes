# Development

Everything needs to pass `cargo clippy` which is set fairly aggressively, also `fmt` and `test`.

There are manual/integration tests which use the AWS CLI to test "real world" usage (`./manual_test.sh` and `scripts/integration/*.sh`).
