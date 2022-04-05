// -*- mode: rust; -*-
//
// This file is part of redjubjub.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Deirdre Connolly <deirdre@zfnd.org>
// - Henry de Valence <hdevalence@hdevalence.ca>

#![allow(non_snake_case)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use curve25519_dalek::{digest::Update, scalar::Scalar};
use sha2::{Digest, Sha512};

pub mod batch;
mod error;
pub mod frost;
pub(crate) mod signature;
mod signing_key;
mod verification_key;

pub use error::Error;
pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};

pub trait Ciphersuite {
    /// An element of the scalar finite field that our group is defined over.
    type Scalar;

    /// An element of our group that we will be computing over.
    type Element;

    /// The order of the the quotient group when the prime order subgroup divides the order of the
    /// full group.
    ///
    /// If using a prime order elliptic curve, the cofactor should be 1 in the scalar field.
    const COFACTOR: Self::Scalar;

    /// H1 for a FROST ciphersuite.
    ///
    /// [spec]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash
    fn H1(m: &[u8]) -> &[u8];

    /// H2 for a FROST ciphersuite.
    ///
    /// [spec]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash
    fn H2(m: &[u8]) -> &[u8];

    /// H3 for a FROST ciphersuite.
    ///
    /// [spec]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash
    fn H3(m: &[u8]) -> &[u8];

    /// Generates the challenge as is required for Schnorr signatures.
    ///
    /// Deals in bytes, so that [FROST] and singleton signing and verification can use it with different
    /// types.
    ///
    /// This is the only invocation of the H2 hash function from the [RFC].
    ///
    /// [FROST]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.html#section-4.6
    /// [RFC]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.html#section-3.2
    fn create_challenge(R_bytes: &[u8; 32], pubkey_bytes: &[u8; 32], msg: &[u8]) -> Self::Scalar;
}
