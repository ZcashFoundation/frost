//! FROST Round 2 functionality and types, for signature share generation

use std::fmt::{self, Debug};

use crate::{
    challenge,
    frost::{self, round1, *},
    Challenge, Ciphersuite, Error, Field, Group, Scalar,
};

/// A representation of a single signature share used in FROST structures and messages.
#[derive(Clone, Copy)]
pub struct SignatureResponse<C: Ciphersuite> {
    /// The scalar contribution to the group signature.
    pub z_share: <<C::Group as Group>::Field as Field>::Scalar,
}

impl<C> SignatureResponse<C>
where
    C: Ciphersuite,
{
    /// Deserialize [`SignatureResponse`] from bytes
    pub fn from_bytes(
        bytes: <<C::Group as Group>::Field as Field>::Serialization,
    ) -> Result<Self, Error> {
        <<C::Group as Group>::Field as Field>::deserialize(&bytes)
            .map(|scalar| Self { z_share: scalar })
    }

    /// Serialize [`SignatureResponse`] to bytes
    pub fn to_bytes(&self) -> <<C::Group as Group>::Field as Field>::Serialization {
        <<C::Group as Group>::Field as Field>::serialize(&self.z_share)
    }
}

impl<C> Debug for SignatureResponse<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SignatureResponse")
            .field("z_share", &hex::encode(self.to_bytes()))
            .finish()
    }
}

impl<C> Eq for SignatureResponse<C> where C: Ciphersuite {}

impl<C> PartialEq for SignatureResponse<C>
where
    C: Ciphersuite,
{
    // TODO: should this have any constant-time guarantees? I think signature shares are public.
    fn eq(&self, other: &Self) -> bool {
        self.z_share == other.z_share
    }
}

/// A participant's signature share, which the coordinator will aggregate with all other signer's
/// shares into the joint signature.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SignatureShare<C: Ciphersuite> {
    /// Represents the participant identifier.
    pub identifier: Identifier<C>,
    /// This participant's signature over the message.
    pub signature: SignatureResponse<C>,
}

impl<C> SignatureShare<C>
where
    C: Ciphersuite,
{
    /// Gets the participant identifier associated with this [`SignatureShare`].
    pub fn identifier(&self) -> &Identifier<C> {
        &self.identifier
    }

    /// Tests if a signature share issued by a participant is valid before
    /// aggregating it into a final joint signature to publish.
    ///
    /// This is the final step of [`verify_signature_share`] from the spec.
    ///
    /// [`verify_signature_share`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-03.html#section-5.3
    pub fn verify(
        &self,
        group_commitment_share: &round1::GroupCommitmentShare<C>,
        public_key: &frost::keys::VerifyingShare<C>,
        lambda_i: <<C::Group as Group>::Field as Field>::Scalar,
        challenge: &Challenge<C>,
    ) -> Result<(), &'static str> {
        if (<C::Group as Group>::generator() * self.signature.z_share)
            != (group_commitment_share.0 + (public_key.0 * challenge.0 * lambda_i))
        {
            return Err("Invalid signature share");
        }

        Ok(())
    }
}

impl<C> Debug for SignatureShare<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SignatureShare")
            .field("identifier", &self.identifier)
            .field("signature", &self.signature)
            .finish()
    }
}

// // Zeroizes `SignatureShare` to be the `Default` value on drop (when it goes out
// // of scope).  Luckily the derived `Default` includes the `Default` impl of
// // Scalar, which is four 0u64's under the hood, and u16, which is
// // 0u16.
// impl DefaultIsZeroes for SignatureShare {}

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
pub fn sign<C: Ciphersuite>(
    signing_package: &SigningPackage<C>,
    signer_nonces: &round1::SigningNonces<C>,
    key_package: &frost::keys::KeyPackage<C>,
) -> Result<SignatureShare<C>, &'static str> {
    // Encodes the signing commitment list produced in round one as part of generating [`Rho`], the
    // binding factor.
    let rho: frost::Rho<C> = signing_package.into();

    // Compute the group commitment from signing commitments produced in round one.
    let group_commitment = GroupCommitment::<C>::try_from(signing_package)?;

    // Compute Lagrange coefficient.
    let lambda_i = frost::derive_lagrange_coeff(key_package.identifier(), signing_package)?;

    // Compute the per-message challenge.
    let challenge = challenge::<C>(
        &group_commitment.0,
        &key_package.group_public.element,
        signing_package.message.as_slice(),
    );

    // Compute the Schnorr signature share.
    let z_share: <<C::Group as Group>::Field as Field>::Scalar = signer_nonces.hiding.0
        + (signer_nonces.binding.0 * rho.0)
        + (lambda_i * key_package.secret_share.0 * challenge.0);

    let signature_share = SignatureShare::<C> {
        identifier: *key_package.identifier(),
        signature: SignatureResponse::<C> { z_share },
    };

    Ok(signature_share)
}
