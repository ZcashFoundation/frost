//! Schnorr signature signing keys

use rand_core::{CryptoRng, RngCore};

use crate::{
    random_nonzero, Challenge, Ciphersuite, Error, Field, Group, Scalar, Signature, SigningTarget,
    VerifyingKey,
};

/// A signing key for a Schnorr signature on a FROST [`Ciphersuite::Group`].
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SigningKey<C>
where
    C: Ciphersuite,
{
    pub(crate) scalar: Scalar<C>,
}

impl<C> SigningKey<C>
where
    C: Ciphersuite,
{
    /// Generate a new signing key.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> SigningKey<C> {
        let scalar = random_nonzero::<C, R>(rng);

        SigningKey { scalar }
    }

    /// Deserialize from bytes
    pub fn deserialize(
        bytes: <<C::Group as Group>::Field as Field>::Serialization,
    ) -> Result<SigningKey<C>, Error<C>> {
        let scalar =
            <<C::Group as Group>::Field as Field>::deserialize(&bytes).map_err(Error::from)?;

        if scalar == <<C::Group as Group>::Field as Field>::zero() {
            return Err(Error::MalformedSigningKey);
        }

        Ok(Self { scalar })
    }

    /// Serialize `SigningKey` to bytes
    pub fn serialize(&self) -> <<C::Group as Group>::Field as Field>::Serialization {
        <<C::Group as Group>::Field as Field>::serialize(&self.scalar)
    }

    /// Create a signature on the given `sig_target` using this `SigningKey`.
    pub fn sign<R: RngCore + CryptoRng>(
        &self,
        mut rng: R,
        sig_target: impl Into<SigningTarget<C>>,
    ) -> Signature<C> {
        let sig_target = sig_target.into();

        let public = VerifyingKey::<C>::from(*self);
        let secret = <C>::effective_secret_key(self.scalar, &public, &sig_target.sig_params);

        let mut k = random_nonzero::<C, R>(&mut rng);
        let mut R = <C::Group>::generator() * k;
        k = <C>::effective_nonce_secret(k, &R);
        R = <C>::effective_nonce_element(R);

        // Generate Schnorr challenge
        let c: Challenge<C> = <C>::challenge(&R, &public, &sig_target);

        <C>::single_sig_finalize(k, R, secret, &c, &public, &sig_target.sig_params)
    }

    /// Creates a SigningKey from a scalar.
    pub fn from_scalar(
        scalar: <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar,
    ) -> Self {
        Self { scalar }
    }

    /// Return the underlying scalar.
    pub fn to_scalar(self) -> <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar {
        self.scalar
    }
}

impl<C> std::fmt::Debug for SigningKey<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SigningKey").field(&"<redacted>").finish()
    }
}

impl<C> From<&SigningKey<C>> for VerifyingKey<C>
where
    C: Ciphersuite,
{
    fn from(signing_key: &SigningKey<C>) -> Self {
        VerifyingKey {
            element: C::Group::generator() * signing_key.scalar,
        }
    }
}

impl<C> From<SigningKey<C>> for VerifyingKey<C>
where
    C: Ciphersuite,
{
    fn from(signing_key: SigningKey<C>) -> Self {
        VerifyingKey::<C>::from(&signing_key)
    }
}
