# ZF FROST (Flexible Round-Optimised Schnorr Threshold signatures)

[![CI](https://github.com/ZcashFoundation/frost/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/ZcashFoundation/frost/actions/workflows/main.yml)

| Crate                        |                        | Crates.io                                                                                                           | Documentation                                                                                        |
| ---------------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Generic FROST implementation | [`frost-core`]         | [![crates.io](https://img.shields.io/crates/v/frost-core.svg)](https://crates.io/crates/frost-core)                 | [![Documentation](https://docs.rs/frost-core/badge.svg)](https://docs.rs/frost-core)                 |
| Ristretto255 ciphersuite     | [`frost-ristretto255`] | [![crates.io](https://img.shields.io/crates/v/frost-ristretto255.svg)](https://crates.io/crates/frost-ristretto255) | [![Documentation](https://docs.rs/frost-ristretto255/badge.svg)](https://docs.rs/frost-ristretto255) |
| Ed25519 ciphersuite          | [`frost-ed25519`]      | [![crates.io](https://img.shields.io/crates/v/frost-ed25519.svg)](https://crates.io/crates/frost-ed25519)           | [![Documentation](https://docs.rs/frost-ed25519/badge.svg)](https://docs.rs/frost-ed25519)           |
| Ed448 ciphersuite            | [`frost-ed448`]        | [![crates.io](https://img.shields.io/crates/v/frost-ed448.svg)](https://crates.io/crates/frost-ed448)               | [![Documentation](https://docs.rs/frost-ed448/badge.svg)](https://docs.rs/frost-ed448)               |
| P-256 ciphersuite            | [`frost-p256`]         | [![crates.io](https://img.shields.io/crates/v/frost-p256.svg)](https://crates.io/crates/frost-p256)                 | [![Documentation](https://docs.rs/frost-p256/badge.svg)](https://docs.rs/frost-p256)                 |
| secp256k1 ciphersuite        | [`frost-secp256k1`]    | [![crates.io](https://img.shields.io/crates/v/frost-secp256k1.svg)](https://crates.io/crates/frost-secp256k1)       | [![Documentation](https://docs.rs/frost-secp256k1/badge.svg)](https://docs.rs/frost-secp256k1)       |
| Generic Re-randomized FROST  | [`frost-rerandomized`] | [![crates.io](https://img.shields.io/crates/v/frost-rerandomized.svg)](https://crates.io/crates/frost-rerandomized) | [![Documentation](https://docs.rs/frost-rerandomized/badge.svg)](https://docs.rs/frost-rerandomized) |

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
to prior Schnorr-based threshold signature constructions.

Besides FROST itself, this repository also provides:

- Trusted dealer key generation as specified in the appendix of ['Two-Round Threshold Schnorr Signatures with FROST'](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/);
- Distributed key generation as specified in the original paper [FROST20](https://eprint.iacr.org/2020/852.pdf);
- Repairable Threshold Scheme (RTS) from ['A Survey and Refinement of Repairable Threshold Schemes'](https://eprint.iacr.org/2017/1155) which allows a participant to recover a lost share with the help of a threshold of other participants;
- Rerandomized FROST (paper under review).
- Refresh Share functionality using a Trusted Dealer. This can be used to refresh the shares of the participants or to remove a participant.

## Getting Started

Refer to the [ZF FROST book](https://frost.zfnd.org/).

## Status ⚠

The FROST specification is not yet finalized, though no significant changes are
expected at this point. This code base has been partially audited by NCC, see
below for details. The APIs and types in the crates contained in this repository
follow SemVer guarantees.

### NCC Audit

NCC performed [an
audit](https://research.nccgroup.com/2023/10/23/public-report-zcash-frost-security-assessment/)
of the v0.6.0 release (corresponding to commit 5fa17ed) of the following crates:

- frost-core
- frost-ed25519
- frost-ed448
- frost-p256
- frost-secp256k1
- frost-ristretto255

This includes key generation (both trusted dealer and DKG) and FROST signing.
This does not include rerandomized FROST.

The parts of the
[`Ed448-Goldilocks`](https://github.com/crate-crypto/Ed448-Goldilocks)
dependency that are used by `frost-ed448` were also in scope, namely the
elliptic curve operations.

All issues identified in the audit were addressed by us and reviewed by NCC.


## Usage

`frost-core` implements the base traits and types in a generic manner, to enable top-level
implementations for different ciphersuites / curves without having to implement all of FROST from
scratch. End-users should not use `frost-core` if they want to sign and verify signatures, they
should use the crate specific to their ciphersuite/curve parameters that uses `frost-core` as a
dependency.

