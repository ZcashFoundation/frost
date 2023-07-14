//! Rerandomized FROST implementation.
//!
//! To sign with rerandomized FROST:
//!
//! - Do Round 1 the same way as regular FROST;
//! - The Coordinator should generate a [`RandomizedParams`] and send
//!   the [`RandomizedParams::randomizer`] to all participants, using a
//!   confidential channel, along with the regular [`SigningPackage`];
//! - Each participant should call [`sign`] and send the resulting
//!   [`SignatureShare`] back to the Coordinator;
//! - The Coordinator should then call [`aggregate`].
#![allow(non_snake_case)]

#[cfg(any(test, feature = "test-impl"))]
pub mod tests;

use std::collections::HashMap;

use derive_getters::Getters;
pub use frost_core;

use frost_core::{
    frost::{
        self,
        keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare},
    },
    Ciphersuite, Error, Field, Group, Scalar, VerifyingKey,
};

// When pulled into `reddsa`, that has its own sibling `rand_core` import.
// For the time being, we do not re-export this `rand_core`.
use rand_core::{CryptoRng, RngCore};

trait Randomize<C> {
    fn randomize(&self, params: &RandomizedParams<C>) -> Result<Self, Error<C>>
    where
        Self: Sized,
        C: Ciphersuite;
}

impl<C: Ciphersuite> Randomize<C> for KeyPackage<C> {
    /// Randomize the given [`KeyPackage`] for usage in a rerandomized FROST signing,
    /// using the given [`RandomizedParams`].
    ///
    /// It's recommended to use [`sign`] directly which already handles
    /// the key package randomization.
    ///
    /// You MUST NOT reuse the randomized key package for more than one signing.
    fn randomize(&self, randomized_params: &RandomizedParams<C>) -> Result<Self, Error<C>>
    where
        Self: Sized,
        C: Ciphersuite,
    {
        let verifying_share = self.public();
        let randomized_verifying_share = VerifyingShare::<C>::new(
            verifying_share.to_element() + randomized_params.randomizer_element,
        );

        let signing_share = self.secret_share();
        let randomized_signing_share =
            SigningShare::new(signing_share.to_scalar() + randomized_params.randomizer);

        let randomized_key_package = KeyPackage::new(
            *self.identifier(),
            randomized_signing_share,
            randomized_verifying_share,
            randomized_params.randomized_verifying_key,
        );
        Ok(randomized_key_package)
    }
}

impl<C: Ciphersuite> Randomize<C> for PublicKeyPackage<C> {
    /// Randomized the given [`PublicKeyPackage`] for usage in a rerandomized FROST
    /// aggregation, using the given [`RandomizedParams`].
    ///
    /// It's recommended to use [`aggregate`] directly which already handles
    /// the public key package randomization.
    fn randomize(&self, randomized_params: &RandomizedParams<C>) -> Result<Self, Error<C>>
    where
        Self: Sized,
        C: Ciphersuite,
    {
        let verifying_shares = self.signer_pubkeys().clone();
        let randomized_verifying_shares = verifying_shares
            .iter()
            .map(|(identifier, verifying_share)| {
                (
                    *identifier,
                    VerifyingShare::<C>::new(
                        verifying_share.to_element() + randomized_params.randomizer_element,
                    ),
                )
            })
            .collect();

        Ok(PublicKeyPackage::new(
            randomized_verifying_shares,
            randomized_params.randomized_verifying_key,
        ))
    }
}

/// Rerandomized FROST signing using the given `randomizer`, which should
/// be sent from the Coordinator using a confidential channel.
///
/// See [`frost::round2::sign`] for documentation on the other parameters.
pub fn sign<C: Ciphersuite>(
    signing_package: &frost::SigningPackage<C>,
    signer_nonces: &frost::round1::SigningNonces<C>,
    key_package: &frost::keys::KeyPackage<C>,
    randomizer: &Scalar<C>,
) -> Result<frost::round2::SignatureShare<C>, Error<C>> {
    let randomized_params =
        RandomizedParams::from_randomizer(key_package.group_public(), randomizer)?;
    let randomized_key_package = key_package.randomize(&randomized_params)?;
    frost::round2::sign(signing_package, signer_nonces, &randomized_key_package)
}

/// Rerandomized FROST signature share aggregation with the given [`RandomizedParams`],
/// which can be computed from the previously generated randomizer using
/// [`RandomizedParams::from_randomizer`].
///
/// See [`frost::aggregate`] for documentation on the other parameters.
pub fn aggregate<C>(
    signing_package: &frost::SigningPackage<C>,
    signature_shares: &HashMap<frost::Identifier<C>, frost::round2::SignatureShare<C>>,
    pubkeys: &frost::keys::PublicKeyPackage<C>,
    randomized_params: &RandomizedParams<C>,
) -> Result<frost_core::Signature<C>, Error<C>>
where
    C: Ciphersuite,
{
    let randomized_public_key_package = pubkeys.randomize(randomized_params)?;
    frost::aggregate(
        signing_package,
        signature_shares,
        &randomized_public_key_package,
    )
}

/// Randomized parameters for a signing instance of randomized FROST.
#[derive(Clone, PartialEq, Eq, Getters)]
pub struct RandomizedParams<C: Ciphersuite> {
    /// The randomizer, also called α
    randomizer: frost_core::Scalar<C>,
    /// The generator multiplied by the randomizer.
    randomizer_element: <C::Group as Group>::Element,
    /// The randomized group public key. The group public key added to the randomizer element.
    randomized_verifying_key: frost_core::VerifyingKey<C>,
}

impl<C> RandomizedParams<C>
where
    C: Ciphersuite,
{
    /// Create a new RandomizedParams for the given [`VerifyingKey`] and
    /// the given `participants`.
    pub fn new<R: RngCore + CryptoRng>(
        group_verifying_key: &VerifyingKey<C>,
        mut rng: R,
    ) -> Result<Self, Error<C>> {
        let randomizer = <<C::Group as Group>::Field as Field>::random(&mut rng);
        Self::from_randomizer(group_verifying_key, &randomizer)
    }

    /// Create a new RandomizedParams for the given [`VerifyingKey`] and the
    /// given `participants` for the  given `randomizer`. The `randomizer` MUST
    /// be generated uniformly at random! Use [`RandomizedParams::new()`] which
    /// generates a fresh randomizer, unless your application requires generating
    /// a randomizer outside.
    pub fn from_randomizer(
        group_verifying_key: &VerifyingKey<C>,
        randomizer: &Scalar<C>,
    ) -> Result<Self, Error<C>> {
        let randomizer_element = <C::Group as Group>::generator() * *randomizer;
        let group_public_element = group_verifying_key.to_element();
        let randomized_group_public_element = group_public_element + randomizer_element;
        let randomized_verifying_key = VerifyingKey::<C>::new(randomized_group_public_element);

        Ok(Self {
            randomizer: *randomizer,
            randomizer_element,
            randomized_verifying_key,
        })
    }
}
