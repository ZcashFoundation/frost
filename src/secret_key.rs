use std::{convert::TryFrom, marker::PhantomData};

use crate::{
    Binding, Error, PublicKey, PublicKeyBytes, Randomizer, Scalar, SigType, Signature, SpendAuth,
};

use rand_core::{CryptoRng, RngCore};

/// A RedJubJub secret key.
#[derive(Copy, Clone, Debug)]
pub struct SecretKey<T: SigType> {
    sk: Scalar,
    pk: PublicKey<T>,
}

impl<T: SigType> From<SecretKey<T>> for [u8; 32] {
    fn from(sk: SecretKey<T>) -> [u8; 32] {
        sk.sk.to_bytes()
    }
}

impl<T: SigType> From<[u8; 32]> for SecretKey<T> {
    fn from(bytes: [u8; 32]) -> Self {
        let sk = {
            // XXX-jubjub: would be nice to unconditionally deser
            // This incantation ensures deserialization is infallible.
            let mut wide = [0; 64];
            wide[0..32].copy_from_slice(&bytes);
            Scalar::from_bytes_wide(&wide)
        };
        let pk = PublicKey::from_secret(&sk);
        SecretKey { sk, pk }
    }
}

/*
impl<R, T> From<R> for SecretKey<T>
where
    R: RngCore + CryptoRng,
    T: SigType,
{
    fn from(mut rng: R) -> SecretKey<T> {
        let mut bytes = [0; 64];
        rng.fill_bytes(&mut bytes);
        SecretKey {
            sk: Scalar::from_bytes_wide(&bytes),
            _marker: PhantomData,
        }
    }
}
*/

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
