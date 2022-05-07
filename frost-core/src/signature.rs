//! Schnorr signatures over prime order groups (or subgroups)

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

// impl<C> Signature<C>
// where
//     C: Ciphersuite,
// {
//     fn from_bytes(bytes: C::SignatureSerialization) -> Signature<C> {

//         // Signature {
//         //     R:
//         //     z:
//         // }
//     }

//     fn to_bytes(&self) -> C::SignatureSerialization {

//         // Signature {
//         //     R:
//         //     z:
//         // }
//     }
// }

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

// impl<C: Ciphersuite> hex::FromHex for Signature<C> {
//     type Error = &'static str;

//     fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
//         let mut bytes = [0u8; 64];

//         match hex::decode_to_slice(hex, &mut bytes[..]) {
//             Ok(()) => Ok(Self::from(bytes)),
//             Err(_) => Err("invalid hex"),
//         }
//     }
// }
