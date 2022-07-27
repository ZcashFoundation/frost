//! Shared code for `frost-ristretto255` integration tests.
//!
//! # Warning
//!
//! Test functions in this file and its submodules will not be run.
//! This file is only for test library code.
//!
//! This module uses the legacy directory structure,
//! to avoid compiling an empty "common" test binary:
//! <https://doc.rust-lang.org/book/ch11-03-test-organization.html#submodules-in-integration-tests>

pub mod ciphersuite;
