//! FROST Round 2 functionality and types, for signature share generation

use std::{
    collections::HashMap,
    fmt::{self, Debug},
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};

use zeroize::DefaultIsZeroes;

use crate::{
    frost::{self, round1},
    generate_challenge, H3,
};

/// Generated by the coordinator of the signing operation and distributed to
/// each signing party
#[derive(Debug)]
pub struct SigningPackage {
    /// The set of commitments participants published in the first round of the
    /// protocol.
    signing_commitments: HashMap<u16, round1::SigningCommitments>,
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
        mut signing_commitments: Vec<round1::SigningCommitments>,
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

    /// Get a signing commitment by its participant index.
    pub fn signing_commitment(&self, index: &u16) -> round1::SigningCommitments {
        self.signing_commitments[index]
    }

    /// Get the signing commitments, sorted by the participant indices
    pub fn signing_commitments(&self) -> Vec<round1::SigningCommitments> {
        let mut signing_commitments: Vec<round1::SigningCommitments> =
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
    pub(super) fn rho_preimage(&self) -> Vec<u8> {
        let mut preimage = vec![];

        preimage.extend_from_slice(
            &round1::encode_group_commitments(self.signing_commitments())[..],
        );
        preimage.extend_from_slice(&H3(self.message.as_slice()));

        preimage
    }
}

/// A representation of a single signature share used in FROST structures and messages, including
/// the group commitment share.
#[derive(Clone, Copy, Default, PartialEq)]
pub struct SignatureResponse {
    pub(super) R_share: round1::GroupCommitmentShare,
    pub(super) z_share: Scalar,
}

impl Debug for SignatureResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
    pub(super) index: u16,
    /// This participant's signature over the message.
    pub(super) signature: SignatureResponse,
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
        group_commitment_share: round1::GroupCommitmentShare,
        public_key: &frost::keys::Public,
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

/// The product of all signers' individual commitments, published as part of the
/// final signature.
#[derive(PartialEq)]
pub struct GroupCommitment(pub(super) RistrettoPoint);

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
        let rho: frost::Rho = signing_package.into();

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
    signer_nonces: &round1::SigningNonces,
    signer_commitments: &round1::SigningCommitments,
    key_package: &frost::keys::KeyPackage,
) -> Result<SignatureShare, &'static str> {
    let rho: frost::Rho = signing_package.into();

    let group_commitment = GroupCommitment::try_from(signing_package)?;

    let challenge = generate_challenge(
        &group_commitment.0.compress().to_bytes(),
        &key_package.group_public.bytes.bytes,
        signing_package.message.as_slice(),
    );

    let lambda_i = frost::generate_lagrange_coeff(key_package.index, signing_package)?;

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
