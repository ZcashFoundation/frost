use std::{convert::TryFrom, marker::PhantomData};

use crate::{
    Binding, Error, PublicKey, PublicKeyBytes, Randomizer, Scalar, SigType, Signature, SpendAuth,
};

use rand_core::{CryptoRng, RngCore};

/// A RedJubJub secret key.
#[derive(Copy, Clone, Debug)]
pub struct SecretKey<T: SigType> {
    sk: Scalar,
    _marker: PhantomData<T>,
}

impl<T: SigType> From<SecretKey<T>> for [u8; 32] {
    fn from(sk: SecretKey<T>) -> [u8; 32] {
        sk.sk.to_bytes()
    }
}

impl<T: SigType> TryFrom<[u8; 32]> for SecretKey<T> {
    type Error = Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        // XXX-jubjub: it does not make sense for this to be a CtOption...
        // XXX-jubjub: this takes a borrow but point deser doesn't
        let maybe_sk = Scalar::from_bytes(&bytes);
        if maybe_sk.is_some().into() {
            Ok(SecretKey {
                sk: maybe_sk.unwrap(),
                _marker: PhantomData,
            })
        } else {
            Err(Error::MalformedSecretKey)
        }
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

impl<'a> From<&'a SecretKey<SpendAuth>> for PublicKey<SpendAuth> {
    fn from(sk: &'a SecretKey<SpendAuth>) -> PublicKey<SpendAuth> {
        // XXX-jubjub: this is pretty baroque
        // XXX-jubjub: provide basepoint tables for generators
        let basepoint: jubjub::ExtendedPoint =
            jubjub::AffinePoint::from_bytes(crate::constants::SPENDAUTHSIG_BASEPOINT_BYTES)
                .unwrap()
                .into();
        pk_from_sk_inner(sk, basepoint)
    }
}

impl<'a> From<&'a SecretKey<Binding>> for PublicKey<Binding> {
    fn from(sk: &'a SecretKey<Binding>) -> PublicKey<Binding> {
        let basepoint: jubjub::ExtendedPoint =
            jubjub::AffinePoint::from_bytes(crate::constants::BINDINGSIG_BASEPOINT_BYTES)
                .unwrap()
                .into();
        pk_from_sk_inner(sk, basepoint)
    }
}

fn pk_from_sk_inner<T: SigType>(
    sk: &SecretKey<T>,
    basepoint: jubjub::ExtendedPoint,
) -> PublicKey<T> {
    let point = &basepoint * &sk.sk;
    let bytes = PublicKeyBytes {
        bytes: jubjub::AffinePoint::from(&point).to_bytes(),
        _marker: PhantomData,
    };
    PublicKey { bytes, point }
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
