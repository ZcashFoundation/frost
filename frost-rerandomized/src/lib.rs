//! FROST implementation supporting re-randomizable keys.
//!
//! To sign with re-randomized FROST:
//!
//! - Do Round 1 the same way as regular FROST;
//! - The Coordinator should call [`RandomizedParams::new()`] and send
//!   the [`RandomizedParams::randomizer`] to all participants, using a
//!   confidential channel, along with the regular [`frost::SigningPackage`];
//! - Each participant should call [`sign`] and send the resulting
//!   [`frost::round2::SignatureShare`] back to the Coordinator;
//! - The Coordinator should then call [`aggregate`].
#![no_std]
#![allow(non_snake_case)]

extern crate alloc;

#[cfg(any(test, feature = "test-impl"))]
pub mod tests;

use alloc::{collections::BTreeMap, string::ToString, vec::Vec};

use derive_getters::Getters;
pub use frost_core;

#[cfg(feature = "serialization")]
use frost_core::SigningPackage;
use frost_core::{
    self as frost,
    keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare},
    serialization::SerializableScalar,
    Ciphersuite, Error, Field, Group, Scalar, VerifyingKey,
};

#[cfg(feature = "serde")]
use frost_core::serde;

// When pulled into `reddsa`, that has its own sibling `rand_core` import.
// For the time being, we do not re-export this `rand_core`.
#[cfg(feature = "serialization")]
use rand_core::{CryptoRng, RngCore};

/// Randomize the given key type for usage in a FROST signing with re-randomized keys,
/// using the given [`RandomizedParams`].
trait Randomize<C> {
    fn randomize(&self, params: &RandomizedParams<C>) -> Result<Self, Error<C>>
    where
        Self: Sized,
        C: Ciphersuite;
}

/// A Ciphersuite that supports rerandomization.
pub trait RandomizedCiphersuite: Ciphersuite {
    /// A hash function that hashes into a randomizer scalar.
    fn hash_randomizer(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar>;
}

impl<C: Ciphersuite> Randomize<C> for KeyPackage<C> {
    /// Randomize the given [`KeyPackage`] for usage in a re-randomized FROST signing,
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
        let verifying_share = self.verifying_share();
        let randomized_verifying_share = VerifyingShare::<C>::new(
            verifying_share.to_element() + randomized_params.randomizer_element,
        );

        let signing_share = self.signing_share();
        let randomized_signing_share =
            SigningShare::new(signing_share.to_scalar() + randomized_params.randomizer.to_scalar());

        let randomized_key_package = KeyPackage::new(
            *self.identifier(),
            randomized_signing_share,
            randomized_verifying_share,
            randomized_params.randomized_verifying_key,
            *self.min_signers(),
        );
        Ok(randomized_key_package)
    }
}

impl<C: Ciphersuite> Randomize<C> for PublicKeyPackage<C> {
    /// Randomized the given [`PublicKeyPackage`] for usage in a re-randomized FROST
    /// aggregation, using the given [`RandomizedParams`].
    ///
    /// It's recommended to use [`aggregate`] directly which already handles
    /// the public key package randomization.
    fn randomize(&self, randomized_params: &RandomizedParams<C>) -> Result<Self, Error<C>>
    where
        Self: Sized,
        C: Ciphersuite,
    {
        let verifying_shares = self.verifying_shares().clone();
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

/// Re-randomized FROST signing using the given `randomizer`, which should
/// be sent from the Coordinator using a confidential channel.
///
/// See [`frost::round2::sign`] for documentation on the other parameters.
pub fn sign<C: RandomizedCiphersuite>(
    signing_package: &frost::SigningPackage<C>,
    signer_nonces: &frost::round1::SigningNonces<C>,
    key_package: &frost::keys::KeyPackage<C>,
    randomizer: Randomizer<C>,
) -> Result<frost::round2::SignatureShare<C>, Error<C>> {
    let randomized_params =
        RandomizedParams::from_randomizer(key_package.verifying_key(), randomizer);
    let randomized_key_package = key_package.randomize(&randomized_params)?;
    frost::round2::sign(signing_package, signer_nonces, &randomized_key_package)
}

/// Re-randomized FROST signature share aggregation with the given [`RandomizedParams`],
/// which can be computed from the previously generated randomizer using
/// [`RandomizedParams::from_randomizer`].
///
/// See [`frost::aggregate`] for documentation on the other parameters.
pub fn aggregate<C>(
    signing_package: &frost::SigningPackage<C>,
    signature_shares: &BTreeMap<frost::Identifier<C>, frost::round2::SignatureShare<C>>,
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

/// A randomizer. A random scalar which is used to randomize the key.
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "C: Ciphersuite"))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(feature = "serde", serde(crate = "self::serde"))]
pub struct Randomizer<C: Ciphersuite>(SerializableScalar<C>);

impl<C> Randomizer<C>
where
    C: Ciphersuite,
{
    pub(crate) fn to_scalar(self) -> Scalar<C> {
        self.0 .0
    }
}

impl<C> Randomizer<C>
where
    C: RandomizedCiphersuite,
{
    /// Create a new random Randomizer.
    ///
    /// The [`SigningPackage`] must be the signing package being used in the
    /// current FROST signing run. It is hashed into the randomizer calculation,
    /// which binds it to that specific package.
    #[cfg(feature = "serialization")]
    pub fn new<R: RngCore + CryptoRng>(
        mut rng: R,
        signing_package: &SigningPackage<C>,
    ) -> Result<Self, Error<C>> {
        let rng_randomizer = <<C::Group as Group>::Field as Field>::random(&mut rng);
        Self::from_randomizer_and_signing_package(rng_randomizer, signing_package)
    }

    /// Create a final Randomizer from a random Randomizer and a SigningPackage.
    /// Function refactored out for testing, should always be private.
    #[cfg(feature = "serialization")]
    fn from_randomizer_and_signing_package(
        rng_randomizer: <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar,
        signing_package: &SigningPackage<C>,
    ) -> Result<Randomizer<C>, Error<C>>
    where
        C: RandomizedCiphersuite,
    {
        let randomizer = C::hash_randomizer(
            &[
                <<C::Group as Group>::Field>::serialize(&rng_randomizer).as_ref(),
                &signing_package.serialize()?,
            ]
            .concat(),
        )
        .ok_or(Error::SerializationError)?;
        Ok(Self(SerializableScalar(randomizer)))
    }
}

impl<C> Randomizer<C>
where
    C: Ciphersuite,
{
    /// Create a new Randomizer from the given scalar. It MUST be randomly
    /// generated.
    ///
    /// It is not recommended to use this method unless for compatibility
    /// reasons with specifications on how the randomizer must be generated. Use
    /// [`Randomizer::new()`] instead.
    pub fn from_scalar(scalar: Scalar<C>) -> Self {
        Self(SerializableScalar(scalar))
    }

    /// Serialize the identifier using the ciphersuite encoding.
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize()
    }

    /// Deserialize an Identifier from a serialized buffer.
    /// Returns an error if it attempts to deserialize zero.
    pub fn deserialize(buf: &[u8]) -> Result<Self, Error<C>> {
        Ok(Self(SerializableScalar::deserialize(buf)?))
    }
}

impl<C> core::fmt::Debug for Randomizer<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Randomizer")
            .field(&hex::encode(self.0.serialize()))
            .finish()
    }
}

/// Randomized parameters for a signing instance of randomized FROST.
#[derive(Clone, PartialEq, Eq, Getters)]
pub struct RandomizedParams<C: Ciphersuite> {
    /// The randomizer, also called α
    randomizer: Randomizer<C>,
    /// The generator multiplied by the randomizer.
    randomizer_element: <C::Group as Group>::Element,
    /// The randomized group public key. The group public key added to the randomizer element.
    randomized_verifying_key: frost_core::VerifyingKey<C>,
}

impl<C> RandomizedParams<C>
where
    C: RandomizedCiphersuite,
{
    /// Create a new [`RandomizedParams`] for the given [`VerifyingKey`] and
    /// the given `participants`.
    #[cfg(feature = "serialization")]
    pub fn new<R: RngCore + CryptoRng>(
        group_verifying_key: &VerifyingKey<C>,
        signing_package: &SigningPackage<C>,
        rng: R,
    ) -> Result<Self, Error<C>> {
        Ok(Self::from_randomizer(
            group_verifying_key,
            Randomizer::new(rng, signing_package)?,
        ))
    }
}

impl<C> RandomizedParams<C>
where
    C: Ciphersuite,
{
    /// Create a new [`RandomizedParams`] for the given [`VerifyingKey`] and the
    /// given `participants` for the  given `randomizer`. The `randomizer` MUST
    /// be generated uniformly at random! Use [`RandomizedParams::new()`] which
    /// generates a fresh randomizer, unless your application requires generating
    /// a randomizer outside.
    pub fn from_randomizer(
        group_verifying_key: &VerifyingKey<C>,
        randomizer: Randomizer<C>,
    ) -> Self {
        let randomizer_element = <C::Group as Group>::generator() * randomizer.to_scalar();
        let verifying_key_element = group_verifying_key.to_element();
        let randomized_verifying_key_element = verifying_key_element + randomizer_element;
        let randomized_verifying_key = VerifyingKey::<C>::new(randomized_verifying_key_element);

        Self {
            randomizer,
            randomizer_element,
            randomized_verifying_key,
        }
    }
}

impl<C> core::fmt::Debug for RandomizedParams<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RandomizedParams")
            .field("randomizer", &self.randomizer)
            .field(
                "randomizer_element",
                &<C::Group as Group>::serialize(&self.randomizer_element)
                    .map(hex::encode)
                    .unwrap_or("<invalid>".to_string()),
            )
            .field("randomized_verifying_key", &self.randomized_verifying_key)
            .finish()
    }
}
