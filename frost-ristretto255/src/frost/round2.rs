//! FROST Round 2 functionality and types, for signature share generation

use std::fmt::{self, Debug};

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};

use zeroize::DefaultIsZeroes;

use crate::{
    frost::{self, round1, *},
    generate_challenge,
};

/// A representation of a single signature share used in FROST structures and messages.

#[derive(Clone, Copy, Default, PartialEq)]
pub struct SignatureResponse {
    pub(super) z_share: Scalar,
}

impl Debug for SignatureResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SignatureResponse")
            .field("z_share", &hex::encode(self.z_share.to_bytes()))
            .finish()
    }
}

impl From<SignatureResponse> for [u8; 32] {
    fn from(sig: SignatureResponse) -> [u8; 32] {
        sig.z_share.to_bytes()
    }
}

/// A participant's signature share, which the coordinator will aggregate with all other signer's
/// shares into the joint signature.
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
    ///
    /// This is the final step of [`verify_signature_share`] from the spec.
    ///
    /// [`verify_signature_share`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-03.html#section-5.3
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

/// Performed once by each participant selected for the signing operation.
///
/// Implements [`sign`] from the spec.
///
/// Receives the message to be signed and a set of signing commitments and a set
/// of randomizing commitments to be used in that signing operation, including
/// that for this participant.
///
/// Assumes the participant has already determined which nonce corresponds with
/// the commitment that was assigned by the coordinator in the SigningPackage.
///
/// [`sign`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-03.html#section-5.2
pub fn sign(
    signing_package: &SigningPackage,
    signer_nonces: &round1::SigningNonces,
    signer_commitments: &round1::SigningCommitments,
    key_package: &frost::keys::KeyPackage,
) -> Result<SignatureShare, &'static str> {
    // Encodes the signing commitment list produced in round one as part of generating [`Rho`], the
    // binding factor.
    let rho: frost::Rho = signing_package.into();

    // Compute the group commitment from signing commitments produced in round one.
    let group_commitment = GroupCommitment::try_from(signing_package)?;

    // Compute Lagrange coefficient.
    let lambda_i = frost::derive_lagrange_coeff(key_package.index, signing_package)?;

    // Compute the per-message challenge.
    let challenge = generate_challenge(
        &group_commitment.0.compress().to_bytes(),
        &key_package.group_public.bytes.bytes,
        signing_package.message.as_slice(),
    );

    // Compute the Schnorr signature share.
    let z_share: Scalar = signer_nonces.hiding.0
        + (signer_nonces.binding.0 * rho.0)
        + (lambda_i * key_package.secret_share.0 * challenge);

    let signature_share = SignatureShare {
        index: key_package.index,
        signature: SignatureResponse { z_share },
    };

    Ok(signature_share)
}
