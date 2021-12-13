// -*- mode: rust; -*-
//
// This file is part of frost-ristretto255.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Deirdre Connolly <deirdre@zfnd.org>
// - Henry de Valence <hdevalence@hdevalence.ca>

//! Performs batch Schnorr signature verification on the Ristretto group.
//!
//! Batch verification asks whether *all* signatures in some set are valid,
//! rather than asking whether *each* of them is valid. This allows sharing
//! computations among all signature verifications, performing less work overall
//! at the cost of higher latency (the entire batch must complete), complexity
//! of caller code (which must assemble a batch of signatures across
//! work-items), and loss of the ability to easily pinpoint failing signatures.

use std::convert::TryFrom;

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, VartimeMultiscalarMul},
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::*;

/// A batch verification item.
///
/// This struct exists to allow batch processing to be decoupled from the
/// lifetime of the message. This is useful when using the batch verification
/// API in an async context.
#[derive(Clone, Debug)]
pub struct Item {
    vk_bytes: VerificationKeyBytes,
    sig: Signature,
    c: Scalar,
}

impl<'msg, M: AsRef<[u8]>> From<(VerificationKeyBytes, Signature, &'msg M)> for Item {
    fn from((vk_bytes, sig, msg): (VerificationKeyBytes, Signature, &'msg M)) -> Self {
        // Compute c now to avoid dependency on the msg lifetime.
        let c = Scalar::from_hash(
            Sha512::new()
                .chain(&sig.r_bytes[..])
                .chain(&vk_bytes.bytes[..])
                .chain(msg),
        );
        Self { vk_bytes, sig, c }
    }
}

impl Item {
    /// Perform non-batched verification of this `Item`.
    ///
    /// This is useful (in combination with `Item::clone`) for implementing
    /// fallback logic when batch verification fails. In contrast to
    /// [`VerificationKey::verify`](crate::VerificationKey::verify), which
    /// requires borrowing the message data, the `Item` type is unlinked
    /// from the lifetime of the message.
    #[allow(non_snake_case)]
    pub fn verify_single(self) -> Result<(), Error> {
        VerificationKey::try_from(self.vk_bytes)
            .and_then(|vk| vk.verify_prehashed(&self.sig, self.c))
    }
}

#[derive(Default)]
/// A batch verification context.
pub struct Verifier {
    /// Signature data queued for verification.
    signatures: Vec<Item>,
}

impl Verifier {
    /// Construct a new batch verifier.
    pub fn new() -> Verifier {
        Verifier::default()
    }

    /// Queue an Item for verification.
    pub fn queue<I: Into<Item>>(&mut self, item: I) {
        self.signatures.push(item.into());
    }

    /// Perform batch verification, returning `Ok(())` if all signatures were
    /// valid and `Err` otherwise.
    ///
    /// The batch verification equation is:
    ///
    /// h_G * -[sum(z_i * s_i)]P_G + sum(\[z_i\]R_i + [z_i * c_i]VK_i) = 0_G
    ///
    /// which we split out into:
    ///
    /// h_G * -[sum(z_i * s_i)]P_G + sum(\[z_i\]R_i) + sum([z_i * c_i]VK_i) =
    /// 0_G
    ///
    /// so that we can use multiscalar multiplication speedups.
    ///
    /// where for each signature i,
    /// - VK_i is the verification key;
    /// - R_i is the signature's R value;
    /// - s_i is the signature's s value;
    /// - c_i is the hash of the message and other data;
    /// - z_i is a random 128-bit Scalar;
    /// - h_G is the cofactor of the group;
    /// - P_G is the generator of the subgroup;
    ///
    /// As follows elliptic curve scalar multiplication convention,
    /// scalar variables are lowercase and group point variables
    /// are uppercase. This does not exactly match the RedDSA
    /// notation in the [protocol specification §B.1][ps].
    ///
    /// [ps]: https://zips.z.cash/protocol/protocol.pdf#reddsabatchverify
    #[allow(non_snake_case)]
    pub fn verify<R: RngCore + CryptoRng>(self, mut rng: R) -> Result<(), Error> {
        let n = self.signatures.len();

        let mut VK_coeffs = Vec::with_capacity(n);
        let mut VKs = Vec::with_capacity(n);
        let mut R_coeffs = Vec::with_capacity(self.signatures.len());
        let mut Rs = Vec::with_capacity(self.signatures.len());
        let mut P_coeff_acc = Scalar::zero();

        for item in self.signatures.iter() {
            let (s_bytes, r_bytes, c) = (item.sig.s_bytes, item.sig.r_bytes, item.c);

            let s = Scalar::from_bytes_mod_order(s_bytes);

            let R = {
                match CompressedRistretto::from_slice(&r_bytes).decompress() {
                    Some(point) => point,
                    None => return Err(Error::InvalidSignature),
                }
            };

            let VK = VerificationKey::try_from(item.vk_bytes.bytes)?.point;

            let z = Scalar::random(&mut rng);

            let P_coeff = z * s;
            P_coeff_acc -= P_coeff;

            R_coeffs.push(z);
            Rs.push(R);

            VK_coeffs.push(Scalar::zero() + (z * c));
            VKs.push(VK);
        }

        use std::iter::once;

        let scalars = once(&P_coeff_acc)
            .chain(VK_coeffs.iter())
            .chain(R_coeffs.iter());

        let basepoints = [curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT];
        let points = basepoints.iter().chain(VKs.iter()).chain(Rs.iter());

        let check = RistrettoPoint::vartime_multiscalar_mul(scalars, points);

        if check == RistrettoPoint::identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
