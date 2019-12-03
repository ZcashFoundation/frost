use std::{convert::TryFrom, marker::PhantomData};

use crate::{Binding, Error, PublicKey, Randomizer, Scalar, SigType, Signature, SpendAuth};

use rand_core::{CryptoRng, RngCore};

/// A refinement type indicating that the inner `[u8; 32]` represents an
/// encoding of a RedJubJub secret key.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SecretKeyBytes<T: SigType> {
    bytes: [u8; 32],
    _marker: PhantomData<T>,
}

impl<T: SigType> From<[u8; 32]> for SecretKeyBytes<T> {
    fn from(bytes: [u8; 32]) -> SecretKeyBytes<T> {
        SecretKeyBytes {
            bytes,
            _marker: PhantomData,
        }
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
    sk: Scalar,
    _marker: PhantomData<T>,
}

impl<T: SigType> From<SecretKey<T>> for SecretKeyBytes<T> {
    fn from(sk: SecretKey<T>) -> SecretKeyBytes<T> {
        SecretKeyBytes {
            bytes: sk.sk.to_bytes(),
            _marker: PhantomData,
        }
    }
}

// XXX could this be a From impl?
// not unless there's an infallible conversion from bytes to scalars,
// which is not  currently present in jubjub
impl<T: SigType> TryFrom<SecretKeyBytes<T>> for SecretKey<T> {
    type Error = Error;

    fn try_from(bytes: SecretKeyBytes<T>) -> Result<Self, Self::Error> {
        // XXX-jubjub: it does not make sense for this to be a CtOption...
        // XXX-jubjub: this takes a borrow but point deser doesn't
        let maybe_sk = Scalar::from_bytes(&bytes.bytes);
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
    let bytes = jubjub::AffinePoint::from(&point).to_bytes();
    PublicKey {
        point,
        bytes,
        _marker: PhantomData,
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
