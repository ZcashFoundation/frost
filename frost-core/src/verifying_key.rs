use crate::{Ciphersuite, Error, Group, Signature};

/// A valid verifying key for Schnorr signatures over a FROST [`Ciphersuite::Group`].
#[derive(Copy, Clone, PartialEq)]
pub struct VerifyingKey<C>
where
    C: Ciphersuite,
{
    pub(crate) element: <C::Group as Group>::Element,
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
        let c = crate::challenge::<C>(&signature.R, &self.element, msg);

        // Verify check is h * ( - z * B + R  + c * A) == 0
        //                 h * ( z * B - c * A - R) == 0
        //
        // where h is the cofactor
        let zB = C::Group::generator() * signature.z;
        let cA = self.element * c.0;
        let check = (zB - cA - signature.R) * C::Group::cofactor();

        if check == C::Group::identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
