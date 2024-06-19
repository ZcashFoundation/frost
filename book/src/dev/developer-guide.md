# Developer Guide

# Pre-commit checks

1. Run tests `cargo test`
2. Run formatter `cargo fmt`
3. Check linter `cargo clippy --all-features --all-targets -- -D warnings` and if you want to automatically fix then run `cargo clippy --fix`

# Coverage

Test coverage checks are performed in the pipeline. This is configured here: `.github/workflows/coverage.yaml`
To run these locally:
1. Install coverage tool by running `cargo install cargo-llvm-cov`
2. Run `cargo llvm-cov --ignore-filename-regex '.*(tests).*|benches.rs|gencode|helpers.rs'` (you may be asked if you want to install `llvm-tools-preview`, if so type `Y`)
