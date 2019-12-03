use std::convert::TryFrom;

use crate::Error;

/// A refinement type indicating that the inner `[u8; 32]` represents an
/// encoding of a RedJubJub public key.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PublicKeyBytes(pub [u8; 32]);

impl From<[u8; 32]> for PublicKeyBytes {
    fn from(raw: [u8; 32]) -> PublicKeyBytes {
        PublicKeyBytes(raw)
    }
}

impl From<PublicKeyBytes> for [u8; 32] {
    fn from(refined: PublicKeyBytes) -> [u8; 32] {
        refined.0
    }
}

/// A RedJubJub public key.
// XXX PartialEq, Eq?
#[derive(Copy, Clone, Debug)]
pub struct PublicKey {
    // fields
}

impl From<PublicKey> for PublicKeyBytes {
    fn from(pk: PublicKey) -> PublicKeyBytes {
        unimplemented!();
    }
}

impl TryFrom<PublicKeyBytes> for PublicKey {
    type Error = Error;

    fn try_from(bytes: PublicKeyBytes) -> Result<Self, Self::Error> {
        unimplemented!();
    }
}
