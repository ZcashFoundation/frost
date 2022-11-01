# FROST (Flexible Round-Optimised Schnorr Threshold signatures) Core

Base traits and types in Rust that implement ['Two-Round Threshold Schnorr Signatures with
FROST'](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/) generically for
`frost-core::Ciphersuite` implementations.

## Status ⚠

The FROST specification is not yet finalized, and this codebase has not yet been audited or
released. The APIs and types in `frost-core` are subject to change.

## Usage

`frost-core` implements the base traits and types in a generic manner, to enable top-level
implementations for different ciphersuites / curves without having to implement all of FROST from
scratch. End-users should not use `frost-core` if they want to sign and verify signatures, they
should use the crate specific to their ciphersuite/curve parameters that uses `frost-core` as a
dependency, such as [`frost_ristretto255`](../frost_ristretto255).

## Example

See ciphersuite-specific crates, e.g. [`frost_ristretto255`](../frost_ristretto255).
