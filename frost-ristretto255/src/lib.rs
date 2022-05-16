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

use curve25519_dalek::scalar::Scalar;
use sha2::{digest::Update, Digest, Sha512};

pub mod batch;
mod error;
pub mod frost;
// mod messages;
pub(crate) mod signature;
mod signing_key;
mod verification_key;

pub use error::Error;
pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};

/// Context string 'FROST-RISTRETTO255-SHA512' from the ciphersuite in the [spec]
///
/// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-01.txt
const CONTEXT_STRING: &str = "FROST-RISTRETTO255-SHA512";

/// H1 for FROST(ristretto255, SHA-512)
///
/// [spec]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash
pub(crate) fn H1(m: &[u8]) -> [u8; 64] {
    let h = Sha512::new()
        .chain(CONTEXT_STRING.as_bytes())
        .chain("rho")
        .chain(m);

    let mut output = [0u8; 64];
    output.copy_from_slice(h.finalize().as_slice());
    output
}

/// H2 for FROST(ristretto255, SHA-512)
///
/// [spec]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash-function-dep-hash
pub(crate) fn H2(m: &[u8]) -> [u8; 64] {
    let h = Sha512::new()
        .chain(CONTEXT_STRING.as_bytes())
        .chain("chal")
        .chain(m);

    let mut output = [0u8; 64];
    output.copy_from_slice(h.finalize().as_slice());
    output
}

/// H3 for FROST(ristretto255, SHA-512)
///
/// Yes, this is just an alias for SHA-512.
///
/// [spec]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash-function-dep-hash
pub(crate) fn H3(m: &[u8]) -> [u8; 64] {
    let h = Sha512::new()
        .chain(CONTEXT_STRING.as_bytes())
        .chain("digest")
        .chain(m);

    let mut output = [0u8; 64];
    output.copy_from_slice(h.finalize().as_slice());
    output
}

/// Generates the challenge as is required for Schnorr signatures.
///
/// Deals in bytes, so that [FROST] and singleton signing and verification can use it with different
/// types.
///
/// This is the only invocation of the H2 hash function from the [RFC].
///
/// [FROST]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-03.html#section-4.6
/// [RFC]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-03.html#section-3.2
fn generate_challenge(R_bytes: &[u8; 32], pubkey_bytes: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut preimage = vec![];

    preimage.extend_from_slice(R_bytes);
    preimage.extend_from_slice(pubkey_bytes);
    preimage.extend_from_slice(msg);

    let challenge_wide = H2(&preimage[..]);

    Scalar::from_bytes_mod_order_wide(&challenge_wide)
}
