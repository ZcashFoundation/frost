//! FROST Round 2 functionality and types, for signature share generation

use std::fmt::{self, Debug};

use crate as frost;
use crate::{
    challenge, Challenge, Ciphersuite, Error, Field, Group, {round1, *},
};

#[cfg(feature = "serde")]
use crate::serialization::ScalarSerialization;

// Used to help encoding a SignatureShare. Since it has a Scalar<C> it can't
// be directly encoded with serde, so we use this struct to wrap the scalar.
#[cfg(feature = "serde")]
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "C: Ciphersuite"))]
#[cfg_attr(feature = "serde", serde(try_from = "ScalarSerialization<C>"))]
#[cfg_attr(feature = "serde", serde(into = "ScalarSerialization<C>"))]
struct SignatureShareHelper<C: Ciphersuite>(Scalar<C>);

#[cfg(feature = "serde")]
impl<C> TryFrom<ScalarSerialization<C>> for SignatureShareHelper<C>
where
    C: Ciphersuite,
{
    type Error = Error<C>;

    fn try_from(value: ScalarSerialization<C>) -> Result<Self, Self::Error> {
        <<C::Group as Group>::Field>::deserialize(&value.0)
            .map(|scalar| Self(scalar))
            .map_err(|e| e.into())
    }
}

#[cfg(feature = "serde")]
impl<C> From<SignatureShareHelper<C>> for ScalarSerialization<C>
where
    C: Ciphersuite,
{
    fn from(value: SignatureShareHelper<C>) -> Self {
        Self(<<C::Group as Group>::Field>::serialize(&value.0))
    }
}

/// A participant's signature share, which the coordinator will aggregate with all other signer's
/// shares into the joint signature.
#[derive(Clone, Copy, Eq, PartialEq, Getters)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "C: Ciphersuite"))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
#[cfg_attr(feature = "serde", serde(try_from = "SignatureShareSerialization<C>"))]
#[cfg_attr(feature = "serde", serde(into = "SignatureShareSerialization<C>"))]
pub struct SignatureShare<C: Ciphersuite> {
    /// This participant's signature over the message.
    pub(crate) share: Scalar<C>,
}

impl<C> SignatureShare<C>
where
    C: Ciphersuite,
{
    /// Deserialize [`SignatureShare`] from bytes
    pub fn deserialize(
        bytes: <<C::Group as Group>::Field as Field>::Serialization,
    ) -> Result<Self, Error<C>> {
        <<C::Group as Group>::Field>::deserialize(&bytes)
            .map(|scalar| Self { share: scalar })
            .map_err(|e| e.into())
    }

    /// Serialize [`SignatureShare`] to bytes
    pub fn serialize(&self) -> <<C::Group as Group>::Field as Field>::Serialization {
        <<C::Group as Group>::Field>::serialize(&self.share)
    }

    /// Tests if a signature share issued by a participant is valid before
    /// aggregating it into a final joint signature to publish.
    ///
    /// This is the final step of [`verify_signature_share`] from the spec.
    ///
    /// [`verify_signature_share`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-signature-share-verificatio
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
    pub(crate) fn verify(
        &self,
        identifier: Identifier<C>,
        group_commitment_share: &round1::GroupCommitmentShare<C>,
        verifying_share: &frost::keys::VerifyingShare<C>,
        lambda_i: Scalar<C>,
        challenge: &Challenge<C>,
    ) -> Result<(), Error<C>> {
        if (<C::Group>::generator() * self.share)
            != (group_commitment_share.0 + (verifying_share.0 * challenge.0 * lambda_i))
        {
            return Err(Error::InvalidSignatureShare {
                culprit: identifier,
            });
        }

        Ok(())
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "C: Ciphersuite"))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
struct SignatureShareSerialization<C: Ciphersuite> {
    /// Serialization header
    pub(crate) header: Header<C>,
    share: SignatureShareHelper<C>,
}

#[cfg(feature = "serde")]
impl<C> From<SignatureShareSerialization<C>> for SignatureShare<C>
where
    C: Ciphersuite,
{
    fn from(value: SignatureShareSerialization<C>) -> Self {
        Self {
            share: value.share.0,
        }
    }
}

#[cfg(feature = "serde")]
impl<C> From<SignatureShare<C>> for SignatureShareSerialization<C>
where
    C: Ciphersuite,
{
    fn from(value: SignatureShare<C>) -> Self {
        Self {
            header: Header::default(),
            share: SignatureShareHelper(value.share),
        }
    }
}

impl<C> Debug for SignatureShare<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SignatureShare")
            .field("share", &hex::encode(self.serialize()))
            .finish()
    }
}

/// Compute the signature share for a signing operation.
#[cfg_attr(feature = "internals", visibility::make(pub))]
#[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
fn compute_signature_share<C: Ciphersuite>(
    signer_nonces: &round1::SigningNonces<C>,
    binding_factor: BindingFactor<C>,
    lambda_i: <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar,
    key_package: &keys::KeyPackage<C>,
    challenge: Challenge<C>,
) -> SignatureShare<C> {
    let z_share: <<C::Group as Group>::Field as Field>::Scalar = signer_nonces.hiding.0
        + (signer_nonces.binding.0 * binding_factor.0)
        + (lambda_i * key_package.signing_share.0 * challenge.0);

    SignatureShare::<C> { share: z_share }
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
/// [`sign`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-round-two-signature-share-g
pub fn sign<C: Ciphersuite>(
    signing_package: &SigningPackage<C>,
    signer_nonces: &round1::SigningNonces<C>,
    key_package: &frost::keys::KeyPackage<C>,
) -> Result<SignatureShare<C>, Error<C>> {
    if signing_package.signing_commitments().len() < key_package.min_signers as usize {
        return Err(Error::IncorrectNumberOfCommitments);
    }

    // Validate the signer's commitment is present in the signing package
    let commitment = signing_package
        .signing_commitments
        .get(&key_package.identifier)
        .ok_or(Error::MissingCommitment)?;

    // Validate if the signer's commitment exists
    if &signer_nonces.commitments != commitment {
        return Err(Error::IncorrectCommitment);
    }

    // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
    // binding factor.
    let binding_factor_list: BindingFactorList<C> =
        compute_binding_factor_list(signing_package, &key_package.verifying_key, &[]);
    let binding_factor: frost::BindingFactor<C> = binding_factor_list
        .get(&key_package.identifier)
        .ok_or(Error::UnknownIdentifier)?
        .clone();

    // Compute the group commitment from signing commitments produced in round one.
    let group_commitment = compute_group_commitment(signing_package, &binding_factor_list)?;

    // Compute Lagrange coefficient.
    let lambda_i = frost::derive_interpolating_value(key_package.identifier(), signing_package)?;

    // Compute the per-message challenge.
    let challenge = challenge::<C>(
        &group_commitment.0,
        &key_package.verifying_key,
        signing_package.message.as_slice(),
    );

    // Compute the Schnorr signature share.
    let signature_share = compute_signature_share(
        signer_nonces,
        binding_factor,
        lambda_i,
        key_package,
        challenge,
    );

    Ok(signature_share)
}
