// -*- mode: rust; -*-
//
// This file is part of redjubjub.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Deirdre Connolly <deirdre@zfnd.org>
// - Henry de Valence <hdevalence@hdevalence.ca>

use std::convert::{TryFrom, TryInto};

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::{Error, Signature, VerificationKey};

/// A signing key for a Schnorr signature on the Ristretto group.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "SerdeHelper"))]
#[cfg_attr(feature = "serde", serde(into = "SerdeHelper"))]
pub struct SigningKey {
    sk: Scalar,
    pk: VerificationKey,
}

impl<'a> From<&'a SigningKey> for VerificationKey {
    fn from(sk: &'a SigningKey) -> VerificationKey {
        sk.pk.clone()
    }
}

impl From<SigningKey> for [u8; 32] {
    fn from(sk: SigningKey) -> [u8; 32] {
        sk.sk.to_bytes()
    }
}

impl TryFrom<[u8; 32]> for SigningKey {
    type Error = Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        match Scalar::from_canonical_bytes(bytes) {
            Some(sk) => {
                let pk = VerificationKey::from(&sk);
                return Ok(SigningKey { sk, pk });
            }
            None => Err(Error::MalformedSigningKey),
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
struct SerdeHelper([u8; 32]);

impl TryFrom<SerdeHelper> for SigningKey {
    type Error = Error;

    fn try_from(helper: SerdeHelper) -> Result<Self, Self::Error> {
        helper.0.try_into()
    }
}

impl From<SigningKey> for SerdeHelper {
    fn from(sk: SigningKey) -> Self {
        Self(sk.into())
    }
}

impl SigningKey {
    /// Generate a new signing key.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> SigningKey {
        let sk = {
            let mut bytes = [0; 64];
            rng.fill_bytes(&mut bytes);
            Scalar::from_bytes_mod_order_wide(&bytes)
        };
        let pk = VerificationKey::from(&sk);
        SigningKey { sk, pk }
    }

    /// Create a signature `msg` using this `SigningKey`.
    // Similar to signature::Signer but without boxed errors.
    pub fn sign<R: RngCore + CryptoRng>(&self, mut rng: R, msg: &[u8]) -> Signature {
        // Choose a byte sequence uniformly at random of length
        // (\ell_H + 128)/8 bytes.  For RedJubjub this is (512 + 128)/8 = 80.
        let random_bytes = {
            let mut bytes = [0; 80];
            rng.fill_bytes(&mut bytes);
            bytes
        };

        let nonce = Scalar::from_hash(
            Sha512::new()
                .chain(&random_bytes[..])
                .chain(&self.pk.bytes.bytes[..]) // XXX ugly
                .chain(msg),
        );

        // XXX: does this need `RistrettoPoint::from_uniform_bytes()` ?
        let r_bytes = (RISTRETTO_BASEPOINT_POINT * nonce).compress().to_bytes();

        let c = Scalar::from_hash(
            Sha512::new()
                .chain(&r_bytes[..])
                .chain(&self.pk.bytes.bytes[..]) // XXX ugly
                .chain(msg),
        );

        let s_bytes = (&nonce + &(c * &self.sk)).to_bytes();

        Signature { r_bytes, s_bytes }
    }
}
