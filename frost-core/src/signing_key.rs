use std::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
};

use rand_core::{CryptoRng, RngCore};

use crate::{Ciphersuite, Error, Signature, VerifyingKey};

/// A signing key for a Schnorr signature over the group.
pub trait SigningKey<C: Ciphersuite>: Copy + Clone + Debug {
    /// The signature type that signing with this key will create.
    type Signature: Signature<C>;

    /// Generate a new signing key.
    fn new<R: RngCore + CryptoRng>(mut rng: R) -> Self;

    /// Create a signature `msg` using this `SigningKey`.
    fn sign<R: RngCore + CryptoRng>(&self, mut rng: R, msg: &[u8]) -> Self::Signature;

    /// Parse a signing key from its byte representation.
    fn from_bytes(bytes: &[u8]) -> Self;

    /// Serialize a signing key into its byte representation.
    fn to_bytes(&self) -> &[u8];
}
