//! Schnorr signatures over prime order groups (or subgroups)

use derive_getters::Getters;

use crate::{Ciphersuite, Element, Error, Field, Group, Scalar};

/// A Schnorr signature over some prime order group (or subgroup).
#[derive(Copy, Clone, Eq, PartialEq, Getters)]
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
    pub fn deserialize(bytes: C::SignatureSerialization) -> Result<Self, Error<C>> {
        C::deserialize_signature(bytes)
    }

    /// Converts this signature to its [`Ciphersuite::SignatureSerialization`] in bytes.
    pub fn serialize(&self) -> C::SignatureSerialization {
        C::serialize_signature(self)
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
        serdect::slice::serialize_hex_lower_or_bin(&self.serialize().as_ref(), serializer)
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
        let array = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid byte length"))?;
        let identifier = Signature::deserialize(array)
            .map_err(|err| serde::de::Error::custom(format!("{err}")))?;
        Ok(identifier)
    }
}

impl<C: Ciphersuite> std::fmt::Debug for Signature<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field("R", &hex::encode(<C::Group>::serialize(&self.R).as_ref()))
            .field(
                "z",
                &hex::encode(<<C::Group as Group>::Field>::serialize(&self.z).as_ref()),
            )
            .finish()
    }
}
