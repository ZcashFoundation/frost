//! Schnorr signatures over prime order groups (or subgroups)

use std::fmt::Debug;

// use hex::FromHex;

use crate::{Ciphersuite, Field, Group};

/// A Schnorr signature over some prime order group (or subgroup).
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Signature<C: Ciphersuite> {
    /// The commitment `R` to the signature nonce.
    pub(crate) R: <C::Group as Group>::Element,
    /// The response `z` to the challenge computed from the commitment `R`, the verifying key, and
    /// the message.
    pub(crate) z: <<C::Group as Group>::Field as Field>::Scalar,
}

impl<C> Signature<C>
where
    C: Ciphersuite,
{
    // fn from_bytes(bytes: C::SignatureSerialization) -> Result<Signature<C>, Error> {

    //     // Signature {
    //     //     R:
    //     //     z:
    //     // }
    // }

    /// Converts this signature to its [`C::SignatureSerialization`] in bytes.
    pub fn to_bytes(&self) -> C::SignatureSerialization
    where
        <<C as Ciphersuite>::SignatureSerialization as TryFrom<Vec<u8>>>::Error: Debug,
    {
        let mut bytes = vec![];

        bytes.extend(<C::Group as Group>::serialize(&self.R).as_ref());
        bytes.extend(<<C::Group as Group>::Field as Field>::serialize(&self.z).as_ref());

        bytes.try_into().unwrap()
    }
}

impl<C: Ciphersuite> std::fmt::Debug for Signature<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field(
                "R",
                &hex::encode(<C::Group as Group>::serialize(&self.R).as_ref()),
            )
            .field(
                "z",
                &hex::encode(<<C::Group as Group>::Field as Field>::serialize(&self.z).as_ref()),
            )
            .finish()
    }
}

// impl<C> FromHex for Signature<C>
// where
//     C: Ciphersuite,
// {
//     type Error = &'static str;

//     fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
//         match FromHex::from_hex(hex) {
//             Ok(bytes) => Self::from_bytes(bytes).map_err(|_| "malformed scalar encoding"),
//             Err(_) => Err("invalid hex"),
//         }
//     }
// }
