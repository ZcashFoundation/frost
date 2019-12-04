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

    /// Randomize this public key with the given `randomizer`.
    pub fn randomize(&self, randomizer: Randomizer) -> PublicKey<T> {
        unimplemented!();
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

        Signature{
            r_bytes,
            s_bytes,
            _marker: PhantomData,
        }
    }
}
