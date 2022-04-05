use std::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
};

use crate::{Ciphersuite, Error, Group, Signature, SigningKey};

/// A valid verification key for Schnorr signatures over a prime order group (or subgroup)..
pub trait VerifyingKey<C: Ciphersuite>: Copy + Clone + PartialEq {
    /// The `Signature` type this key verifies.
    type Signature: Signature<C>;

    /// Get the inner group element.
    fn point(&self) -> <C::Group as Group>::Element;

    /// Derive a `VerifyingKey` from a `SigningKey`.
    fn from(s: &SigningKey<C>) -> Self;

    /// Serialize this verifying key into byte representation.
    fn to_bytes(&self) -> &[u8];

    /// Verify a purported `signature` over `msg` made by this verification key.
    fn verify(&self, msg: &[u8], signature: &Self::Signature) -> Result<(), Error> {
        let c = C::challenge(&signature.R().into(), &self.to_bytes(), msg);

        let R = &signature.R();

        let s = &signature.z();

        // Verify check is h * ( - s * B + R  + c * A) == 0
        //                 h * ( s * B - c * A - R) == 0
        let sB = C::Group::BASEPOINT * s;
        let cA = self.point() * c;
        let check = sB - cA - R;

        if check == C::Group::IDENTITY {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
