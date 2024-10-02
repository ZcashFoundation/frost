//! Schnorr signatures over prime order groups (or subgroups)

use alloc::{string::ToString, vec::Vec};

use crate::{Ciphersuite, Element, Error, Field, Group, Scalar};

/// A Schnorr signature over some prime order group (or subgroup).
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Signature<C: Ciphersuite> {
    /// The commitment `R` to the signature nonce.
    pub(crate) R: Element<C>,
    /// The response `z` to the challenge computed from the commitment `R`, the verifying key, and
    /// the message.
    pub(crate) z: Scalar<C>,
}

impl<C> Signature<C>
where
    C: Ciphersuite,
    C::Group: Group,
    <C::Group as Group>::Field: Field,
{
    /// Create a new Signature.
    #[cfg(feature = "internals")]
    pub fn new(
        R: <C::Group as Group>::Element,
        z: <<C::Group as Group>::Field as Field>::Scalar,
    ) -> Self {
        Self { R, z }
    }

    /// Converts bytes as [`Ciphersuite::SignatureSerialization`] into a `Signature<C>`.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error<C>> {
        C::deserialize_signature(bytes)
    }

    /// Converts this signature to its byte serialization.
    pub fn serialize(&self) -> Result<Vec<u8>, Error<C>> {
        <C>::serialize_signature(self)
    }
}

#[cfg(feature = "serde")]
impl<C> serde::Serialize for Signature<C>
where
    C: Ciphersuite,
    C::Group: Group,
    <C::Group as Group>::Field: Field,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(
            &self.serialize().map_err(serde::ser::Error::custom)?,
            serializer,
        )
    }
}

#[cfg(feature = "serde")]
impl<'de, C> serde::Deserialize<'de> for Signature<C>
where
    C: Ciphersuite,
    C::Group: Group,
    <C::Group as Group>::Field: Field,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        let signature = Signature::deserialize(&bytes)
            .map_err(|err| serde::de::Error::custom(format!("{err}")))?;
        Ok(signature)
    }
}

impl<C: Ciphersuite> core::fmt::Debug for Signature<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Signature")
            .field(
                "R",
                &<C::Group>::serialize(&self.R)
                    .map(|s| hex::encode(s.as_ref()))
                    .unwrap_or("<invalid>".to_string()),
            )
            .field(
                "z",
                &hex::encode(<<C::Group as Group>::Field>::serialize(&self.z).as_ref()),
            )
            .finish()
    }
}
