# FROST (Flexible Round-Optimised Schnorr Threshold signatures)

Rust implementations of ['Two-Round Threshold Schnorr Signatures with FROST'](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/).

Unlike signatures in a single-party setting, threshold signatures require cooperation among a
threshold number of signers, each holding a share of a common private key. The security of threshold
schemes in general assume that an adversary can corrupt strictly fewer than a threshold number of
participants.

['Two-Round Threshold Schnorr Signatures with
FROST'](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/) presents a variant of a Flexible
Round-Optimized Schnorr Threshold (FROST) signature scheme originally defined in
[FROST20](https://eprint.iacr.org/2020/852.pdf). FROST reduces network overhead during threshold
signing operations while employing a novel technique to protect against forgery attacks applicable
to prior Schnorr-based threshold signature constructions. This variant of FROST requires two rounds
to compute a signature, and implements signing efficiency improvements described by
[Schnorr21](https://eprint.iacr.org/2021/1375.pdf). Single-round signing with FROST is not
implemented here.

## Status ⚠

The FROST specification is not yet finalized, and this codebase has not yet been audited or
released. The APIs and types in `frost-core` are subject to change.

## Usage

`frost-core` implements the base traits and types in a generic manner, to enable top-level
implementations for different ciphersuites / curves without having to implement all of FROST from
scratch. End-users should not use `frost-core` if they want to sign and verify signatures, they
should use the crate specific to their ciphersuite/curve parameters that uses `frost-core` as a
dependency.

## Pre-commit checks

1. Run tests `cargo test`
2. Run formatter `cargo fmt`
3. Check linter `cargo clippy` and if you want to automatically fix then run `cargo clippy --fix`
