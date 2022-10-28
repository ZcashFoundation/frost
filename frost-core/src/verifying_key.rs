use std::fmt::{self, Debug};

use hex::FromHex;

use crate::{Challenge, Ciphersuite, Element, Error, Group, Signature};

/// A valid verifying key for Schnorr signatures over a FROST [`Ciphersuite::Group`].
#[derive(Copy, Clone, PartialEq)]
pub struct VerifyingKey<C>
where
    C: Ciphersuite,
{
    pub(crate) element: Element<C>,
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
        <C::Group>::deserialize(&bytes).map(|element| VerifyingKey { element })
    }

    /// Serialize `VerifyingKey` to bytes
    pub fn to_bytes(&self) -> <C::Group as Group>::Serialization {
        <C::Group>::serialize(&self.element)
    }

    /// Verify a purported `signature` with a pre-hashed [`Challenge`] made by this verification
    /// key.
    pub(crate) fn verify_prehashed(
        &self,
        challenge: Challenge<C>,
        signature: &Signature<C>,
    ) -> Result<(), Error> {
        // Verify check is h * ( - z * B + R  + c * A) == 0
        //                 h * ( z * B - c * A - R) == 0
        //
        // where h is the cofactor
        let zB = C::Group::generator() * signature.z;
        let cA = self.element * challenge.0;
        let check = (zB - cA - signature.R) * C::Group::cofactor();

        if check == C::Group::identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Verify a purported `signature` over `msg` made by this verification key.
    pub fn verify(&self, msg: &[u8], signature: &Signature<C>) -> Result<(), Error> {
        C::verify_signature(msg, signature, self)
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

#[cfg(any(test, feature = "test-impl"))]
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
