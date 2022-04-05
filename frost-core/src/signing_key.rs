use std::fmt::Debug;

use rand_core::{CryptoRng, RngCore};

use crate::{Ciphersuite, Error, Group, Signature, VerifyingKey};

/// A signing key for a Schnorr signature over the group.
pub trait SigningKey<C: Ciphersuite>: Copy + Clone {
    /// The signature type that signing with this key will create.
    type Signature: Signature<C>;

    /// Generate a new signing key.
    fn new<R: RngCore + CryptoRng>(rng: R) -> Self;

    /// Parse a signing key from its byte representation.
    fn from_bytes(bytes: &[u8]) -> Self;

    /// Serialize a signing key into its byte representation.
    fn to_bytes(&self) -> &[u8];

    /// Get inner type as Scalar.
    fn scalar(&self) -> <C::Group as Group>::Scalar;

    /// Create a signature `msg` using this `SigningKey`.
    fn sign<R: RngCore + CryptoRng>(&self, rng: R, msg: &[u8]) -> Self::Signature {
        // // Choose a byte sequence uniformly at random of length
        // // (\ell_H + 128)/8 bytes.  For RedJubjub this is (512 + 128)/8 = 80.
        // let random_bytes = {
        //     let mut bytes = [0; 80];
        //     rng.fill_bytes(&mut bytes);
        //     bytes
        // };

        // let nonce = Scalar::from_hash(
        //     Sha512::new()
        //         .chain(&random_bytes[..])
        //         .chain(&self.pk.bytes.bytes[..]) // XXX ugly
        //         .chain(msg),
        // );

        let k = <C::Group as Group>::random_nonzero_scalar(rng);

        let R = <C::Group as Group>::BASEPOINT * k;

        // Generate Schnorr challenge
        let c = C::challenge(&R.into(), &self.pubkey_bytes, msg);

        let z = k + (c * self.scalar());

        Self::from_bytes(R.into(), z.into())
    }
}
