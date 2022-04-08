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

impl<C: Ciphersuite> std::fmt::Debug for Signature<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field("R", &hex::encode(<C::Group as Group>::serialize(&self.R)))
            .field(
                "z",
                &hex::encode(<<C::Group as Group>::Field as Field>::serialize(&self.z)),
            )
            .finish()
    }
}

// impl<C: Ciphersuite> From<C::SignatureSerialization> for Signature<C> {
//     fn from(bytes: C::SignatureSerialization) -> Signature<C> {
//         let mut R_bytes = <C::Group as Group>::ElementSerialization
//         R_bytes.copy_from_slice(&bytes[0..32]);
//         let mut z_bytes = [0; 32];
//         z_bytes.copy_from_slice(&bytes[32..64]);
//         Signature { R_bytes, z_bytes }
//     }
// }

// impl<C: Ciphersuite> From<Signature<C>> for [u8; 64] {
//     fn from(sig: Signature<C>) -> [u8; 64] {
//         let mut bytes = [0; 64];
//         bytes[0..32].copy_from_slice(&sig.R_bytes[..]);
//         bytes[32..64].copy_from_slice(&sig.z_bytes[..]);
//         bytes
//     }
// }

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
