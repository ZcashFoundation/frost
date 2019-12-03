use std::{convert::TryFrom, marker::PhantomData};

use crate::{Error, PublicKey, SigType, Binding, SpendAuth, Randomizer, Signature};

/// A refinement type indicating that the inner `[u8; 32]` represents an
/// encoding of a RedJubJub secret key.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SecretKeyBytes<T: SigType> {
    bytes: [u8; 32],
    _marker: PhantomData<T>,
}

impl<T: SigType> From<[u8; 32]> for SecretKeyBytes<T> {
    fn from(bytes: [u8; 32]) -> SecretKeyBytes<T> {
        SecretKeyBytes{ bytes, _marker: PhantomData }
    }
}

impl<T: SigType> From<SecretKeyBytes<T>> for [u8; 32] {
    fn from(refined: SecretKeyBytes<T>) -> [u8; 32] {
        refined.bytes
    }
}

/// A RedJubJub secret key.
// XXX PartialEq, Eq?
#[derive(Copy, Clone, Debug)]
pub struct SecretKey<T: SigType> {
    // fields
    _marker: PhantomData<T>,
}

impl<T: SigType> From<SecretKey<T>> for SecretKeyBytes<T> {
    fn from(pk: SecretKey<T>) -> SecretKeyBytes<T> {
        unimplemented!();
    }
}

// XXX could this be a From impl?
impl<T: SigType> TryFrom<SecretKeyBytes<T>> for SecretKey<T> {
    type Error = Error;

    fn try_from(bytes: SecretKeyBytes<T>) -> Result<Self, Self::Error> {
        unimplemented!();
    }
}

impl<'a, T: SigType> From<&'a SecretKey<T>> for PublicKey<T> {
    fn from(sk: &'a SecretKey<T>) -> PublicKey<T> {
        unimplemented!();
    }
}

impl<T: SigType> SecretKey<T> {
    /// Randomize this public key with the given `randomizer`.
    pub fn randomize(&self, randomizer: Randomizer) -> PublicKey<T> {
        unimplemented!();
    }
}

impl SecretKey<Binding> {
    /// Create a Zcash `BindingSig` on `msg` using this `SecretKey`.
    // Similar to signature::Signer but without boxed errors.
    pub fn sign(&self, msg: &[u8]) -> Signature<Binding> {
        // could use sign_inner
        unimplemented!();
    }
}

impl SecretKey<SpendAuth> {
    /// Create a Zcash `SpendAuthSig` on `msg` using this `SecretKey`.
    // Similar to signature::Signer but without boxed errors.
    pub fn sign(&self, msg: &[u8]) -> Signature<SpendAuth> {
        // could use sign_inner
        unimplemented!();
    }
}
