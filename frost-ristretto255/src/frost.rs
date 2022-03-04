// -*- mode: rust; -*-
//
// This file is part of frost-ristretto255.
// Copyright (c) 2020-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Chelsea H. Komlo <me@chelseakomlo.com>
// - Deirdre Connolly <deirdre@zfnd.org>
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! An implementation of FROST (Flexible Round-Optimized Schnorr Threshold)
//! signatures.
//!
//! If you are interested in deploying FROST, please do not hesitate to consult the FROST authors.
//!
//! This implementation currently only supports key generation using a central
//! dealer. In the future, we will add support for key generation via a DKG,
//! as specified in the FROST paper.
//!
//! Internally, keygen_with_dealer generates keys using Verifiable Secret
//! Sharing,  where shares are generated using Shamir Secret Sharing.

use std::{
    collections::HashMap,
    convert::TryFrom,
    fmt::{self, Debug},
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{self, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use hex::FromHex;
use rand_core::{CryptoRng, RngCore};
use zeroize::DefaultIsZeroes;

pub mod keys;

#[cfg(test)]
mod tests;

use crate::{generate_challenge, Signature, H1, H3};

/// A scalar used in Ristretto that is a signing nonce.
#[derive(Clone, Copy, Default, PartialEq)]
pub(crate) struct Nonce(pub(crate) Scalar);

impl Nonce {
    /// Generates a new uniformly random signing nonce.
    ///
    /// Each participant generates signing nonces before performing a signing
    /// operation.
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        // The values of 'hiding' and 'binding' nonces must be non-zero so that commitments are
        // not the identity.
        Self(Scalar::random(rng))
    }
}

impl AsRef<Scalar> for Nonce {
    fn as_ref(&self) -> &Scalar {
        &self.0
    }
}

impl Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Nonce")
            .field(&hex::encode(self.0.to_bytes()))
            .finish()
    }
}

// Zeroizes `Secret` to be the `Default` value on drop (when it goes out of scope).  Luckily the
// derived `Default` includes the `Default` impl of Scalar, which is four 0u64's under the hood.
impl DefaultIsZeroes for Nonce {}

impl FromHex for Nonce {
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 32];

        match hex::decode_to_slice(hex, &mut bytes[..]) {
            Ok(()) => Self::try_from(bytes),
            Err(_) => Err("invalid hex"),
        }
    }
}

impl TryFrom<[u8; 32]> for Nonce {
    type Error = &'static str;

    fn try_from(source: [u8; 32]) -> Result<Self, &'static str> {
        match Scalar::from_canonical_bytes(source) {
            Some(scalar) => Ok(Self(scalar)),
            None => Err("ristretto scalar were not canonical byte representation"),
        }
    }
}

/// A Ristretto point that is a commitment to a signing nonce share.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct NonceCommitment(pub(crate) RistrettoPoint);

impl From<Nonce> for NonceCommitment {
    fn from(nonce: Nonce) -> Self {
        Self(RISTRETTO_BASEPOINT_POINT * nonce.0)
    }
}

impl FromHex for NonceCommitment {
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 32];

        match hex::decode_to_slice(hex, &mut bytes[..]) {
            Ok(()) => Self::try_from(bytes),
            Err(_) => Err("invalid hex"),
        }
    }
}

impl TryFrom<[u8; 32]> for NonceCommitment {
    type Error = &'static str;

    fn try_from(source: [u8; 32]) -> Result<Self, &'static str> {
        match ristretto::CompressedRistretto::from_slice(&source[..]).decompress() {
            Some(point) => Ok(Self(point)),
            None => Err("ristretto point was not canonically encoded"),
        }
    }
}

/// The product of all signers' individual commitments, published as part of the
/// final signature.
#[derive(PartialEq)]
pub struct GroupCommitment(pub(crate) RistrettoPoint);

impl Debug for GroupCommitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("GroupCommitment")
            .field(&hex::encode(self.0.compress().to_bytes()))
            .finish()
    }
}

impl TryFrom<&SigningPackage> for GroupCommitment {
    type Error = &'static str;

    /// Generates the group commitment which is published as part of the joint
    /// Schnorr signature.
    fn try_from(signing_package: &SigningPackage) -> Result<GroupCommitment, &'static str> {
        let rho: Rho = signing_package.into();

        let identity = RistrettoPoint::identity();
        let mut accumulator = identity;

        // Ala the sorting of B, just always sort by index in ascending order
        //
        // https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#encoding-operations-dep-encoding
        for commitment in signing_package.signing_commitments() {
            // The following check prevents a party from accidentally revealing their share.
            // Note that the '&&' operator would be sufficient.
            if identity == commitment.binding.0 || identity == commitment.hiding.0 {
                return Err("Commitment equals the identity.");
            }

            accumulator += commitment.hiding.0 + (commitment.binding.0 * rho.0)
        }

        Ok(GroupCommitment(accumulator))
    }
}

/// Comprised of hiding and binding nonces.
///
/// Note that [`SigningNonces`] must be used *only once* for a signing
/// operation; re-using nonces will result in leakage of a signer's long-lived
/// signing key.
#[derive(Clone, Copy, Default, Debug)]
pub struct SigningNonces {
    hiding: Nonce,
    binding: Nonce,
}

// Zeroizes `SigningNonces` to be the `Default` value on drop (when it goes out of scope).  Luckily
// the derived `Default` includes the `Default` impl of the `curve25519_dalek::scalar::Scalar`s,
// which is 32 0u8's under the hood.
impl DefaultIsZeroes for SigningNonces {}

impl SigningNonces {
    /// Generates a new signing nonce.
    ///
    /// Each participant generates signing nonces before performing a signing
    /// operation.
    pub fn new<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        // The values of 'hiding' and 'binding' must be non-zero so that commitments are
        // not the identity.
        let hiding = Nonce::random(rng);
        let binding = Nonce::random(rng);

        Self { hiding, binding }
    }
}

/// Published by each participant in the first round of the signing protocol.
///
/// This step can be batched if desired by the implementation. Each
/// SigningCommitment can be used for exactly *one* signature.
#[derive(Copy, Clone, Debug)]
pub struct SigningCommitments {
    /// The participant index
    pub(crate) index: u16,
    /// The hiding point.
    pub(crate) hiding: NonceCommitment,
    /// The binding point.
    pub(crate) binding: NonceCommitment,
}

impl SigningCommitments {
    fn to_group_commitment_share(&self, binding_factor: &Rho) -> GroupCommitmentShare {
        GroupCommitmentShare(self.hiding.0 + (self.binding.0 * binding_factor.0))
    }
}

impl From<(u16, &SigningNonces)> for SigningCommitments {
    fn from((index, nonces): (u16, &SigningNonces)) -> Self {
        Self {
            index,
            hiding: nonces.hiding.into(),
            binding: nonces.binding.into(),
        }
    }
}

/// One signer's share of the group commitment, derived from their individual signing commitments
/// and the binding factor _rho_.
///
/// Used to verify signature shares.
#[derive(Clone, Copy, Default, PartialEq)]
pub struct GroupCommitmentShare(RistrettoPoint);

/// Encode the list of group signing commitments.
///
/// Inputs:
/// - commitment_list = [(j, D_j, E_j), ...], a list of commitments issued by each signer,
///   where each element in the list indicates the signer index and their
///   two commitment Element values. B MUST be sorted in ascending order
///   by signer index.
///
/// Outputs:
/// - A byte string containing the serialized representation of B.
///
/// <https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#encoding-operations-dep-encoding>
fn encode_group_commitments(signing_commitments: Vec<SigningCommitments>) -> Vec<u8> {
    // B MUST be sorted in ascending order by signer index.
    //
    // https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#encoding-operations-dep-encoding
    let mut sorted_signing_commitments = signing_commitments;
    sorted_signing_commitments.sort_by_key(|a| a.index);

    let mut bytes = vec![];

    for item in sorted_signing_commitments {
        bytes.extend_from_slice(&item.index.to_be_bytes()[..]);
        bytes.extend_from_slice(&item.hiding.0.compress().to_bytes()[..]);
        bytes.extend_from_slice(&item.binding.0.compress().to_bytes()[..]);
    }

    bytes
}

/// Generated by the coordinator of the signing operation and distributed to
/// each signing party
#[derive(Debug)]
pub struct SigningPackage {
    /// The set of commitments participants published in the first round of the
    /// protocol.
    signing_commitments: HashMap<u16, SigningCommitments>,
    /// Message which each participant will sign.
    ///
    /// Each signer should perform protocol-specific verification on the
    /// message.
    message: Vec<u8>,
}

impl SigningPackage {
    /// Create a new `SigingPackage`
    ///
    /// The `signing_commitments` are sorted by participant `index`.
    pub fn new(
        mut signing_commitments: Vec<SigningCommitments>,
        message: Vec<u8>,
    ) -> SigningPackage {
        signing_commitments.sort_by_key(|a| a.index);

        SigningPackage {
            signing_commitments: signing_commitments
                .into_iter()
                .map(|s| (s.index, s))
                .collect(),
            message,
        }
    }

    /// Get the signing commitments, sorted by the participant indices
    pub fn signing_commitments(&self) -> Vec<SigningCommitments> {
        let mut signing_commitments: Vec<SigningCommitments> =
            self.signing_commitments.values().cloned().collect();
        signing_commitments.sort_by_key(|a| a.index);
        signing_commitments
    }

    /// Get the message to be signed
    pub fn message(&self) -> &Vec<u8> {
        &self.message
    }

    /// Compute the preimage to H3 to compute rho
    // We separate this out into its own method so it can be tested
    fn rho_preimage(&self) -> Vec<u8> {
        let mut preimage = vec![];

        preimage
            .extend_from_slice(&encode_group_commitments(self.signing_commitments().clone())[..]);
        preimage.extend_from_slice(&H3(self.message.as_slice()));

        preimage
    }
}

/// The binding factor, also known as _rho_ (ρ)
///
/// Ensures each signature share is strongly bound to a signing set, specific set
/// of commitments, and a specific message.
///
/// <https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md>
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Rho(Scalar);

impl From<&SigningPackage> for Rho {
    fn from(signing_package: &SigningPackage) -> Rho {
        let preimage = signing_package.rho_preimage();

        let binding_factor = H1(&preimage[..]);

        Rho(Scalar::from_bytes_mod_order_wide(&binding_factor))
    }
}

impl FromHex for Rho {
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 32];

        match hex::decode_to_slice(hex, &mut bytes[..]) {
            Ok(()) => Self::try_from(bytes),
            Err(_) => Err("invalid hex"),
        }
    }
}

impl TryFrom<[u8; 32]> for Rho {
    type Error = &'static str;

    fn try_from(source: [u8; 32]) -> Result<Self, &'static str> {
        match Scalar::from_canonical_bytes(source) {
            Some(scalar) => Ok(Self(scalar)),
            None => Err("scalar was not canonically encoded"),
        }
    }
}

/// A representation of a single signature share used in FROST structures and messages, including
/// the group commitment share.
#[derive(Clone, Copy, Default, PartialEq)]
pub struct SignatureResponse {
    pub(crate) R_share: GroupCommitmentShare,
    pub(crate) z_share: Scalar,
}

impl Debug for SignatureResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("SignatureResponse")
            .field(
                "R_share",
                &hex::encode(self.R_share.0.compress().to_bytes()),
            )
            .field("z_share", &hex::encode(self.z_share.to_bytes()))
            .finish()
    }
}

impl From<SignatureResponse> for [u8; 64] {
    fn from(sig: SignatureResponse) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[0..32].copy_from_slice(&sig.R_share.0.compress().to_bytes());
        bytes[32..64].copy_from_slice(&sig.z_share.to_bytes());
        bytes
    }
}

/// A participant's signature share, which the coordinator will use to aggregate
/// with all other signer's shares into the joint signature.
#[derive(Clone, Copy, Default, PartialEq)]
pub struct SignatureShare {
    /// Represents the participant index.
    pub(crate) index: u16,
    /// This participant's signature over the message.
    pub(crate) signature: SignatureResponse,
}

impl Debug for SignatureShare {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SignatureShare")
            .field("index", &self.index)
            .field("signature", &self.signature)
            .finish()
    }
}

// Zeroizes `SignatureShare` to be the `Default` value on drop (when it goes out
// of scope).  Luckily the derived `Default` includes the `Default` impl of
// Scalar, which is four 0u64's under the hood, and u32, which is
// 0u32.
impl DefaultIsZeroes for SignatureShare {}

impl SignatureShare {
    /// Tests if a signature share issued by a participant is valid before
    /// aggregating it into a final joint signature to publish.
    pub fn verify(
        &self,
        group_commitment_share: GroupCommitmentShare,
        public_key: &keys::Public,
        lambda_i: Scalar,
        challenge: Scalar,
    ) -> Result<(), &'static str> {
        if (RISTRETTO_BASEPOINT_POINT * self.signature.z_share)
            != (group_commitment_share.0 + (public_key.0 * challenge * lambda_i))
        {
            return Err("Invalid signature share");
        }
        Ok(())
    }
}

/// Done once by each participant, to generate _their_ nonces and commitments
/// that are then used during signing.
///
/// When performing signing using two rounds, num_nonces would equal 1, to
/// perform the first round. Batching entails generating more than one
/// nonce/commitment pair at a time.  Nonces should be stored in secret storage
/// for later use, whereas the commitments are published.
///
/// The number of nonces is limited to 255. This limit can be increased if it
/// turns out to be too conservative.
// TODO: Make sure the above is a correct statement, fix if needed in:
// https://github.com/ZcashFoundation/redjubjub/issues/111
pub fn preprocess<R>(
    num_nonces: u8,
    participant_index: u16,
    rng: &mut R,
) -> (Vec<SigningNonces>, Vec<SigningCommitments>)
where
    R: CryptoRng + RngCore,
{
    let mut signing_nonces: Vec<SigningNonces> = Vec::with_capacity(num_nonces as usize);
    let mut signing_commitments: Vec<SigningCommitments> = Vec::with_capacity(num_nonces as usize);

    for _ in 0..num_nonces {
        let nonces = SigningNonces::new(rng);
        signing_commitments.push(SigningCommitments::from((participant_index, &nonces)));
        signing_nonces.push(nonces);
    }

    (signing_nonces, signing_commitments)
}

/// Generates the lagrange coefficient for the i'th participant.
fn generate_lagrange_coeff(
    signer_index: u16,
    signing_package: &SigningPackage,
) -> Result<Scalar, &'static str> {
    let mut num = Scalar::one();
    let mut den = Scalar::one();

    // Ala the sorting of B, just always sort by index in ascending order
    //
    // https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#encoding-operations-dep-encoding
    for commitment in signing_package.signing_commitments() {
        if commitment.index == signer_index {
            continue;
        }
        num *= Scalar::from(commitment.index as u16);
        den *= Scalar::from(commitment.index as u16) - Scalar::from(signer_index as u16);
    }

    if den == Scalar::zero() {
        return Err("Duplicate shares provided");
    }

    // TODO: handle this unwrap better like other CtOption's
    let lagrange_coeff = num * den.invert();

    Ok(lagrange_coeff)
}

/// Performed once by each participant selected for the signing operation.
///
/// Receives the message to be signed and a set of signing commitments and a set
/// of randomizing commitments to be used in that signing operation, including
/// that for this participant.
///
/// Assumes the participant has already determined which nonce corresponds with
/// the commitment that was assigned by the coordinator in the SigningPackage.
pub fn sign(
    signing_package: &SigningPackage,
    signer_nonces: &SigningNonces,
    signer_commitments: &SigningCommitments,
    key_package: &keys::KeyPackage,
) -> Result<SignatureShare, &'static str> {
    let rho: Rho = signing_package.into();

    let group_commitment = GroupCommitment::try_from(signing_package)?;

    let challenge = generate_challenge(
        &group_commitment.0.compress().to_bytes(),
        &key_package.group_public.bytes.bytes,
        signing_package.message.as_slice(),
    );

    let lambda_i = generate_lagrange_coeff(key_package.index, signing_package)?;

    // The Schnorr signature share
    let z_share: Scalar = signer_nonces.hiding.0
        + (signer_nonces.binding.0 * rho.0)
        + (lambda_i * key_package.secret_share.0 * challenge);

    // The Schnorr signature commitment share
    let R_share = signer_commitments.to_group_commitment_share(&rho);

    let signature_share = SignatureShare {
        index: key_package.index,
        signature: SignatureResponse { z_share, R_share },
    };

    Ok(signature_share)
}

/// Verifies each participant's signature share, and if all are valid,
/// aggregates the shares into a signature to publish.
///
/// Resulting signature is compatible with verification of a plain SpendAuth
/// signature.
///
/// This operation is performed by a coordinator that can communicate with all
/// the signing participants before publishing the final signature. The
/// coordinator can be one of the participants or a semi-trusted third party
/// (who is trusted to not perform denial of service attacks, but does not learn
/// any secret information). Note that because the coordinator is trusted to
/// report misbehaving parties in order to avoid publishing an invalid
/// signature, if the coordinator themselves is a signer and misbehaves, they
/// can avoid that step. However, at worst, this results in a denial of
/// service attack due to publishing an invalid signature.
pub fn aggregate(
    signing_package: &SigningPackage,
    signing_shares: &[SignatureShare],
    pubkeys: &keys::PublicKeyPackage,
) -> Result<Signature, &'static str> {
    let group_commitment = GroupCommitment::try_from(signing_package)?;

    let challenge = generate_challenge(
        &group_commitment.0.compress().to_bytes(),
        &pubkeys.group_public.bytes.bytes,
        signing_package.message.as_slice(),
    );

    let rho: Rho = signing_package.into();

    // Verify the signature shares
    for signing_share in signing_shares {
        let signer_pubkey = pubkeys.signer_pubkeys.get(&signing_share.index).unwrap();
        let lambda_i = generate_lagrange_coeff(signing_share.index, signing_package)?;

        let R_share = signing_package.signing_commitments[&signing_share.index]
            .to_group_commitment_share(&rho);

        signing_share.verify(R_share, signer_pubkey, lambda_i, challenge)?;
    }

    // The aggregation of the signature shares by summing them up, resulting in
    // a plain Schnorr signature.
    let mut z = Scalar::zero();

    for signature_share in signing_shares {
        z += signature_share.signature.z_share;
    }

    Ok(Signature {
        R_bytes: group_commitment.0.compress().to_bytes(),
        z_bytes: z.to_bytes(),
    })
}
