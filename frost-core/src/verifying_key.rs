use core::fmt::{self, Debug};

use alloc::{string::ToString, vec::Vec};

#[cfg(any(test, feature = "test-impl"))]
use hex::FromHex;

use crate::{
    serialization::SerializableElement, Challenge, Ciphersuite, Error, Group, Signature,
    SigningTarget,
};

/// A valid verifying key for Schnorr signatures over a FROST [`Ciphersuite::Group`].
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "C: Ciphersuite"))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct VerifyingKey<C>
where
    C: Ciphersuite,
{
    pub(crate) element: SerializableElement<C>,
}

impl<C> VerifyingKey<C>
where
    C: Ciphersuite,
{
    /// Create a new VerifyingKey from the given element.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
    pub(crate) fn new(element: <C::Group as Group>::Element) -> Self {
        Self {
            element: SerializableElement(element),
        }
    }

    /// Return the underlying element.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
    pub(crate) fn to_element(self) -> <C::Group as Group>::Element {
        self.element.0
    }

    /// Return the effective verifying key given the specific signing parameters
    /// to be verified against. For most ciphersuites, this simply returns the
    /// same verifying key unchanged.
    pub fn effective_key(self, sig_params: &C::SigningParameters) -> Self {
        VerifyingKey::new(<C>::effective_pubkey_element(&self, sig_params))
    }

    /// Check if VerifyingKey is odd
    pub fn y_is_odd(&self) -> bool {
        <C::Group as Group>::y_is_odd(&self.to_element())
    }

    /// Deserialize from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<VerifyingKey<C>, Error<C>> {
        Ok(Self::new(SerializableElement::deserialize(bytes)?.0))
    }

    /// Serialize `VerifyingKey` to bytes
    pub fn serialize(&self) -> Result<Vec<u8>, Error<C>> {
        self.element.serialize()
    }

    /// Verify a purported `signature` with a pre-hashed [`Challenge`] made by this verification
    /// key.
    pub(crate) fn verify_prehashed(
        &self,
        challenge: Challenge<C>,
        signature: &Signature<C>,
        sig_params: &C::SigningParameters,
    ) -> Result<(), Error<C>> {
        // Verify check is h * ( - z * B + R  + c * A) == 0
        //                 h * ( z * B - c * A - R) == 0
        //
        // where h is the cofactor
        let R = signature.R;
        let vk = C::effective_pubkey_element(self, sig_params);

        let zB = C::Group::generator() * signature.z;
        let cA = vk * challenge.0;
        let check = (zB - cA - R) * C::Group::cofactor();

        if check == C::Group::identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Verify a purported `signature` over `sig_target` made by this verification key.
    pub fn verify(
        &self,
        sig_target: impl Into<SigningTarget<C>>,
        signature: &Signature<C>,
    ) -> Result<(), Error<C>> {
        C::verify_signature(&sig_target.into(), signature, self)
    }

    /// Computes the group public key given the group commitment.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    pub(crate) fn from_commitment(
        commitment: &crate::keys::VerifiableSecretSharingCommitment<C>,
    ) -> Result<VerifyingKey<C>, Error<C>> {
        Ok(VerifyingKey::new(
            commitment
                .coefficients()
                .first()
                .ok_or(Error::IncorrectCommitment)?
                .value(),
        ))
    }
}

impl<C> Debug for VerifyingKey<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("VerifyingKey")
            .field(
                &self
                    .serialize()
                    .map(hex::encode)
                    .unwrap_or("<invalid>".to_string()),
            )
            .finish()
    }
}

#[cfg(any(test, feature = "test-impl"))]
impl<C> FromHex for VerifyingKey<C>
where
    C: Ciphersuite,
{
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let v: Vec<u8> = FromHex::from_hex(hex).map_err(|_| "invalid hex")?;
        Self::deserialize(&v).map_err(|_| "malformed verifying key encoding")
    }
}
