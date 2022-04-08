//! Schnorr signature signing keys

use rand_core::{CryptoRng, RngCore};

use crate::{Ciphersuite, Error, Field, Group, Signature, VerifyingKey};

/// A signing key for a Schnorr signature on a FROST [`Ciphersuite::Group`].
#[derive(Copy, Clone)]
pub struct SigningKey<C>
where
    C: Ciphersuite,
{
    scalar: <<C::Group as Group>::Field as Field>::Scalar,
}

impl<C> From<&SigningKey<C>> for VerifyingKey<C>
where
    C: Ciphersuite,
{
    fn from(signing_key: &SigningKey<C>) -> VerifyingKey<C> {
        VerifyingKey {
            element: C::Group::generator() * signing_key.scalar,
        }
    }
}

impl<C> SigningKey<C>
where
    C: Ciphersuite,
{
    /// Generate a new signing key.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> SigningKey<C> {
        let scalar = <<C::Group as Group>::Field as Field>::random_nonzero(&mut rng);

        SigningKey { scalar }
    }

    /// Deserialize from bytes
    pub fn from_bytes(
        bytes: <<C::Group as Group>::Field as Field>::Serialization,
    ) -> Result<SigningKey<C>, Error> {
        <<C::Group as Group>::Field as Field>::deserialize(&bytes)
            .map(|scalar| SigningKey { scalar })
    }

    /// Serialize `VerifyingKey` to bytes
    pub fn to_bytes(&self) -> <<C::Group as Group>::Field as Field>::Serialization {
        <<C::Group as Group>::Field as Field>::serialize(&self.scalar)
    }

    /// Create a signature `msg` using this `SigningKey`.
    pub fn sign<R: RngCore + CryptoRng>(&self, mut rng: R, msg: &[u8]) -> Signature<C> {
        let k = <<C::Group as Group>::Field as Field>::random_nonzero(&mut rng);

        let R = <C::Group as Group>::generator() * k;

        // Generate Schnorr challenge
        let c = crate::challenge::<C>(&R, &VerifyingKey::from(self).element, msg);

        let z = k + (c * self.scalar);

        Signature { R, z }
    }
}
