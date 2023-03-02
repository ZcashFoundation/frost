# FROST (Flexible Round-Optimised Schnorr Threshold signatures) Rerandomized

Base traits and types in Rust that implement ['Two-Round Threshold Schnorr Signatures with
FROST'](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/) generically for
`frost-core::Ciphersuite` implementations, with support for Zcash-compatible
RedDSA re-randomized signatures.

## Status ⚠

The FROST specification is not yet finalized, and this codebase has not yet been audited or
released. The APIs and types in `frost-rerandomized` are subject to change.

## Usage

`frost-rerandomized` is similar to `frost-core`, but provides different
`sign()` and `aggregate()` functions adding support for re-randomized signatures.
End-users should not use `frost-rerandomized` if they want to sign and verify signatures, they
should use the crate specific to their ciphersuite/curve parameters that uses `frost-rerandomized` as a
dependency, such as [`reddsa`](https://github.com/ZcashFoundation/reddsa/).

## Example

See ciphersuite-specific modules, e.g. the ones in [`reddsa`](https://github.com/ZcashFoundation/reddsa/).
