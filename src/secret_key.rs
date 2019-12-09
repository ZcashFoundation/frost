use std::{
    convert::{TryFrom, TryInto},
    marker::PhantomData,
};

use crate::{Error, PublicKey, Randomizer, Scalar, SigType, Signature, SpendAuth};

use rand_core::{CryptoRng, RngCore};

/// A RedJubJub secret key.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "SerdeHelper"))]
#[cfg_attr(feature = "serde", serde(into = "SerdeHelper"))]
#[cfg_attr(feature = "serde", serde(bound = "T: SigType"))]
pub struct SecretKey<T: SigType> {
    sk: Scalar,
    pk: PublicKey<T>,
}

impl<'a, T: SigType> From<&'a SecretKey<T>> for PublicKey<T> {
    fn from(sk: &'a SecretKey<T>) -> PublicKey<T> {
        sk.pk.clone()
    }
}

impl<T: SigType> From<SecretKey<T>> for [u8; 32] {
    fn from(sk: SecretKey<T>) -> [u8; 32] {
        sk.sk.to_bytes()
    }
}

impl<T: SigType> TryFrom<[u8; 32]> for SecretKey<T> {
    type Error = Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        // XXX-jubjub: this should not use CtOption
        let maybe_sk = Scalar::from_bytes(&bytes);
        if maybe_sk.is_some().into() {
            let sk = maybe_sk.unwrap();
            let pk = PublicKey::from_secret(&sk);
            Ok(SecretKey { sk, pk })
        } else {
            Err(Error::MalformedSecretKey)
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
struct SerdeHelper([u8; 32]);

impl<T: SigType> TryFrom<SerdeHelper> for SecretKey<T> {
    type Error = Error;

    fn try_from(helper: SerdeHelper) -> Result<Self, Self::Error> {
        helper.0.try_into()
    }
}

impl<T: SigType> From<SecretKey<T>> for SerdeHelper {
    fn from(sk: SecretKey<T>) -> Self {
        Self(sk.into())
    }
}

impl SecretKey<SpendAuth> {
    /// Randomize this public key with the given `randomizer`.
    pub fn randomize(&self, randomizer: &Randomizer) -> SecretKey<SpendAuth> {
        let sk = &self.sk + randomizer;
        let pk = PublicKey::from_secret(&sk);
        SecretKey { sk, pk }
    }
}

impl<T: SigType> SecretKey<T> {
    /// Generate a new secret key.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> SecretKey<T> {
        let sk = {
            let mut bytes = [0; 64];
            rng.fill_bytes(&mut bytes);
            Scalar::from_bytes_wide(&bytes)
        };
        let pk = PublicKey::from_secret(&sk);
        SecretKey { sk, pk }
    }

    /// Create a signature of type `T` on `msg` using this `SecretKey`.
    // Similar to signature::Signer but without boxed errors.
    pub fn sign<R: RngCore + CryptoRng>(&self, mut rng: R, msg: &[u8]) -> Signature<T> {
        use crate::HStar;

        // Choose a byte sequence uniformly at random of length
        // (\ell_H + 128)/8 bytes.  For RedJubjub this is (512 + 128)/8 = 80.
        let random_bytes = {
            let mut bytes = [0; 80];
            rng.fill_bytes(&mut bytes);
            bytes
        };

        let nonce = HStar::default()
            .update(&random_bytes[..])
            .update(&self.pk.bytes.bytes[..]) // XXX ugly
            .update(msg)
            .finalize();

        let r_bytes = jubjub::AffinePoint::from(&T::basepoint() * &nonce).to_bytes();

        let c = HStar::default()
            .update(&r_bytes[..])
            .update(&self.pk.bytes.bytes[..]) // XXX ugly
            .update(msg)
            .finalize();

        let s_bytes = (&nonce + &(&c * &self.sk)).to_bytes();

        Signature {
            r_bytes,
            s_bytes,
            _marker: PhantomData,
        }
    }
}
