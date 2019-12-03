use std::convert::TryFrom;

use crate::{Error, Randomizer, PublicKey, Signature};

/// A refinement type indicating that the inner `[u8; 32]` represents an
/// encoding of a RedJubJub secret key.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SecretKeyBytes(pub [u8; 32]);

impl From<[u8; 32]> for SecretKeyBytes {
    fn from(raw: [u8; 32]) -> SecretKeyBytes {
        SecretKeyBytes(raw)
    }
}

impl From<SecretKeyBytes> for [u8; 32] {
    fn from(refined: SecretKeyBytes) -> [u8; 32] {
        refined.0
    }
}

/// A RedJubJub secret key.
// XXX PartialEq, Eq?
#[derive(Copy, Clone, Debug)]
pub struct SecretKey {
    // fields
}

impl From<SecretKey> for SecretKeyBytes {
    fn from(pk: SecretKey) -> SecretKeyBytes {
        unimplemented!();
    }
}

// XXX could this be a From impl?
impl TryFrom<SecretKeyBytes> for SecretKey {
    type Error = Error;

    fn try_from(bytes: SecretKeyBytes) -> Result<Self, Self::Error> {
        unimplemented!();
    }
}

impl<'a> From<&'a SecretKey> for PublicKey {
    fn from(sk: &'a SecretKey) -> PublicKey {
        unimplemented!();
    }
}

impl SecretKey {
    /// Randomize this public key with the given `randomizer`.
    pub fn randomize(&self, randomizer: Randomizer) -> PublicKey {
        unimplemented!();
    }

    /// Sign the given `msg` with this `SecretKey`.
    // Similar to signature::Signer but without boxed errors.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        unimplemented!();
    }
}
