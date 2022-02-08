// -*- mode: rust; -*-
//
// This file is part of redjubjub.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Deirdre Connolly <deirdre@zfnd.org>
// - Henry de Valence <hdevalence@hdevalence.ca>

use std::{
    convert::{TryFrom, TryInto},
    hash::{Hash, Hasher},
};

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use sha2::{Digest, Sha512};

use crate::{Error, Signature, frost};


/// A refinement type for `[u8; 32]` indicating that the bytes represent an
/// encoding of a verification key for Schnorr signatures over the Ristretto
/// group.
///
/// This is useful for representing a compressed verification key; the
/// [`VerificationKey`] type in this library holds other decompressed state
/// used in signature verification.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerificationKeyBytes {
    pub(crate) bytes: [u8; 32],
}

impl From<[u8; 32]> for VerificationKeyBytes {
    fn from(bytes: [u8; 32]) -> VerificationKeyBytes {
        VerificationKeyBytes { bytes }
    }
}

impl From<VerificationKeyBytes> for [u8; 32] {
    fn from(refined: VerificationKeyBytes) -> [u8; 32] {
        refined.bytes
    }
}

impl Hash for VerificationKeyBytes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

/// A valid verification key for Schnorr signatures over the Ristretto group.
///
/// This type holds decompressed state used in signature verification; if the
/// verification key may not be used immediately, it is probably better to use
/// [`VerificationKeyBytes`], which is a refinement type for `[u8; 32]`.
///
/// ## Consensus properties
///
/// The `TryFrom<VerificationKeyBytes>` conversion performs the following Zcash
/// consensus rule checks:
///
/// 1. The check that the bytes are a canonical encoding of a verification key;
/// 2. The check that the verification key is not a point of small order.
#[derive(PartialEq, Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "VerificationKeyBytes"))]
#[cfg_attr(feature = "serde", serde(into = "VerificationKeyBytes"))]
pub struct VerificationKey {
    pub(crate) point: RistrettoPoint,
    pub(crate) bytes: VerificationKeyBytes,
}

impl From<VerificationKey> for VerificationKeyBytes {
    fn from(pk: VerificationKey) -> VerificationKeyBytes {
        pk.bytes
    }
}

impl From<VerificationKey> for [u8; 32] {
    fn from(pk: VerificationKey) -> [u8; 32] {
        pk.bytes.bytes
    }
}

impl TryFrom<VerificationKeyBytes> for VerificationKey {
    type Error = Error;

    fn try_from(bytes: VerificationKeyBytes) -> Result<Self, Self::Error> {
        // This checks that the encoding is canonical...
        match CompressedRistretto::from_slice(&bytes.bytes).decompress() {
            Some(point) => Ok(VerificationKey { point, bytes }),
            None => Err(Error::MalformedVerificationKey),
        }
    }
}

impl TryFrom<[u8; 32]> for VerificationKey {
    type Error = Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        VerificationKeyBytes::from(bytes).try_into()
    }
}

impl VerificationKey {
    pub(crate) fn from(s: &Scalar) -> VerificationKey {
        let point = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT * s;
        let bytes = VerificationKeyBytes {
            bytes: point.compress().to_bytes(),
        };
        VerificationKey { bytes, point }
    }

    /// Verify a purported `signature` over `msg` made by this verification key.
    // This is similar to impl signature::Verifier but without boxed errors
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        let msg_hash = frost::H3(msg);

        self.verify_prehashed(
            signature,
            Scalar::from_hash(
                Sha512::new()
                    .chain(&signature.r_bytes[..])
                    .chain(&self.bytes.bytes[..])
                    .chain(msg_hash),
            ),
        )
    }

    /// Verify a purported `signature` with a prehashed challenge.
    #[allow(non_snake_case)]
    pub(crate) fn verify_prehashed(&self, signature: &Signature, c: Scalar) -> Result<(), Error> {
        let r = match CompressedRistretto::from_slice(&signature.r_bytes).decompress() {
            Some(point) => point,
            None => return Err(Error::InvalidSignature),
        };

        let s = match Scalar::from_canonical_bytes(signature.s_bytes) {
            Some(s) => s,
            None => return Err(Error::InvalidSignature),
        };

        // XXX rewrite as normal double scalar mul
        // Verify check is h * ( - s * B + R  + c * A) == 0
        //                 h * ( s * B - c * A - R) == 0
        let sB = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT * &s;
        let cA = &self.point * &c;
        let check = sB - cA - r;

        if check == RistrettoPoint::identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
