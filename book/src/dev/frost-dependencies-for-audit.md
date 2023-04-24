# FROST dependencies

This is a list of production Rust code that is in scope and out of scope for FROSTs second audit.

--
## Full Audit 

### FROST Crates

| Name | Version | Notes
|------| ------- | -----
| frost-core | v0.2.0 |
| frost-ed25519 | v0.2.0 |
| frost-ed448 | v0.2.0 |
| frost-p256 | v0.2.0 |
| frost-ristretto255 | v0.2.0 |
| frost-secp256k1 | v0.2.0 |

### ZF Dependencies

| Name | Version | Notes
|------| ------- | -----
| redjubjub | v0.6.0 | This library is being partially audited as part of the [Zebra audit](https://github.com/ZcashFoundation/zebra-private/blob/d4137908385be7e6df0a935b91bfc83b532261a2/book/src/dev/zebra-dependencies-for-audit.md#zcashzf-dependencies-1). 
| reddsa | v0.5.0 | This library is being partially audited as part of the [Zebra audit](https://github.com/ZcashFoundation/zebra-private/blob/d4137908385be7e6df0a935b91bfc83b532261a2/book/src/dev/zebra-dependencies-for-audit.md#zcashzf-dependencies-1). 

---
## Partial Audit

| Name | Version | Reason | Notes
|------| ------- | -----  | -----
| ed448-goldilocks | v0.4.0 | Doesn't have a lot of users on github (12) or crates.io (~2k recent downloads) and it's not been previously audited and reviewed | A pure-Rust implementation of Ed448 and Curve448 and Decaf. 

The following ed448-goldilocks modules are used by frost-ed448:
- `src/field/scalar.rs`
- `src/curve/edwards/extended.rs` (converting to/from TwistedExtendedPoint, MontgomeryPoint and AffinePoint are out of scope)
- `src/field/mod.rs`
- `src/curve/scalar_mul/variable_base.rs`

---
## Out of Scope

The following crates and dependencies are out of scope for the audit.

### FROST Crates

| Name | Version | Notes
|------| ------- | -----
| frost-rerandomized | v0.2.0 | To be audited after the security proof is complete.

### `frost-core` Dependencies

| Name | Version | Reason | Notes
|------| ------- | -----  | -----
| byteorder | v1.4.3 | | Library for reading/writing numbers in big-endian and little-endian.
| criterion | v0.4.0 | | Statistics-driven micro-benchmarking library
| debugless-unwrap | v0.0.4 | | This library provides alternatives to the standard .unwrap* methods on Result and Option that don't require Debug to be implemented on the unexpected variant.
| digest | v0.10.6 | | Traits for cryptographic hash functions and message authentication codes
| hex | v0.4.3 | | Encoding and decoding data into/from hexadecimal representation.
| proptest | v1.1.0 | | Hypothesis-like property-based testing and shrinking.
| proptest-derive | v0.3.0 | | Custom-derive for the Arbitrary trait of proptest.
| rand_core | v0.6.4 | | Core random number generator traits and tools for implementation.
| serde_json | v1.0.93 | | A JSON serialization file format
| thiserror | v1.0.38 | | This library provides a convenient derive macro for the standard library's std::error::Error trait.
| visibility | v0.0.1 | | Attribute to override the visibility of items (useful in conjunction with cfg_attr)
| zeroize | v1.5.7 | | This crate implements a portable approach to securely zeroing memory using techniques which guarantee they won't be "optimized away" by the compiler.

### `frost-ed25519` Dependencies

| Name | Version | Reason | Notes
|------| ------- | -----  | -----
| curve25519-dalek | v4.0.0-pre.1 |  | A pure-Rust implementation of group operations on ristretto255 and Curve25519
| rand_core | v0.6.4 | | Core random number generator traits and tools for implementation.
| sha2 | v0.10.6 | | Pure Rust implementation of the SHA-2 hash function family including SHA-224, SHA-256, SHA-384, and SHA-512.

### `frost-ed448` Dependencies

| Name | Version | Reason | Notes
|------| ------- | -----  | -----
| rand_core | v0.6.4 | | Pure Rust implementation of the SHA-2 hash function family including SHA-224, SHA-256, SHA-384, and SHA-512.
| sha3 | v0.10.6 | | SHA-3 (Keccak) hash function

### `frost-p256` Dependencies

| Name | Version | Reason | Notes
|------| ------- | -----  | -----
| p256 | v0.11.1 | | Pure Rust implementation of the NIST P-256 (a.k.a. secp256r1, prime256v1) elliptic curve with support for ECDH, ECDSA signing/verification, and general purpose curve arithmetic
| rand_core | v0.6.4 | | Core random number generator traits and tools for implementation.
| sha2 | v0.10.6 | | Pure Rust implementation of the SHA-2 hash function family including SHA-224, SHA-256, SHA-384, and SHA-512.

### `frost-rerandomized` Dependencies

| Name | Version | Reason | Notes
|------| ------- | -----  | -----
| rand_core | v0.6.4 | | Core random number generator traits and tools for implementation.

### `frost-ristretto255` Dependencies

_None_

### `frost-secp256k1` Dependencies

| Name | Version | Reason | Notes
|------| ------- | -----  | -----
| k256 | v0.12.0-pre.0 | | secp256k1 (a.k.a. K-256) elliptic curve library written in pure Rust with support for ECDSA signing/verification/public-key recovery, Taproot Schnorr signatures, Elliptic Curve Diffie-Hellman (ECDH), and general-purpose secp256k1 elliptic curve group operations which can be used to implement arbitrary group-based protocols.
| rand_core | v0.6.4 | | Core random number generator traits and tools for implementation.
| sha2 | v0.10.6 | | Pure Rust implementation of the SHA-2 hash function family including SHA-224, SHA-256, SHA-384, and SHA-512.
