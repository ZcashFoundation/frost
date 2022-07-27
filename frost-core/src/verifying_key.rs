use std::fmt::{self, Debug};

use hex::FromHex;

use crate::{Challenge, Ciphersuite, Error, Group, Signature};

/// A valid verifying key for Schnorr signatures over a FROST [`Ciphersuite::Group`].
#[derive(Copy, Clone, PartialEq)]
pub struct VerifyingKey<C>
where
    C: Ciphersuite,
{
    pub(crate) element: <C::Group as Group>::Element,
}

impl<C> VerifyingKey<C>
where
    C: Ciphersuite,
{
    // pub(crate) fn from(scalar: &<<C::Group as Group>::Field as Field>::Scalar) -> Self {
    //     let element = <C::Group as Group>::generator() * *scalar;

    //     VerifyingKey { element }
    // }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: <C::Group as Group>::Serialization) -> Result<VerifyingKey<C>, Error> {
        <C::Group as Group>::deserialize(&bytes).map(|element| VerifyingKey { element })
    }

    /// Serialize `VerifyingKey` to bytes
    pub fn to_bytes(&self) -> <C::Group as Group>::Serialization {
        <C::Group as Group>::serialize(&self.element)
    }

    /// Verify a purported `signature` over `msg` made by this verification key.
    pub fn verify(&self, msg: &[u8], signature: &Signature<C>) -> Result<(), Error> {
        C::VerifySignature(msg, signature, self)
    }
}

impl<C> Debug for VerifyingKey<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("VerifyingKey")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

impl<C> FromHex for VerifyingKey<C>
where
    C: Ciphersuite,
{
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let v: Vec<u8> = FromHex::from_hex(hex).map_err(|_| "invalid hex")?;
        match v.try_into() {
            Ok(bytes) => Self::from_bytes(bytes).map_err(|_| "malformed verifying key encoding"),
            Err(_) => Err("malformed verifying key encoding"),
        }
    }
}

// impl<C: Ciphersuite> From<VerifyingKey<C>> for <C::Group as Group>::ElementSerialization {
//     fn from(pk: VerifyingKey<C>) -> <C::Group as Group>::ElementSerialization {
//         pk.bytes.bytes
//     }
// }

// impl<C: Ciphersuite> TryFrom<<C::Group as Group>::ElementSerialization> for VerifyingKey<C> {
//     type Error = Error;

//     fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
//         VerifyingKeyBytes::from(bytes).try_into()
//     }
// }
