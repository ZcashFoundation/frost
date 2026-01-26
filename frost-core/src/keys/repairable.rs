//! Repairable Threshold Scheme
//!
//! Implements the Repairable Threshold Scheme (RTS) from
//! <https://eprint.iacr.org/2017/1155>. The RTS is used to help a signer
//! (participant) repair their lost share. This is achieved using a subset of
//! the other signers known here as `helpers`.
//!
//! The repair procedure should be run as follows:
//!
//! - Participants need to agree somehow on who are going to be the `helpers`
//!   for the repair, and which participant is going to repair their share.
//! - Each helper runs `repair_share_part1`, generating a set of `delta` values
//!   to be sent to each helper (including themselves).
//! - Each helper runs `repair_share_part2`, passing the received `delta`
//!   values, generating a `sigma` value to be sent to the participant repairing
//!   their share.
//! - The participant repairing their share runs `repair_share_part3`, passing
//!   all the received `sigma` values, recovering their lost `KeyPackage`. (They
//!   will also need the `PublicKeyPackage` for this step which could be
//!   provided by any of the helpers).

use alloc::collections::{BTreeMap, BTreeSet};

use alloc::vec::Vec;

use crate::keys::{KeyPackage, PublicKeyPackage};
use crate::serialization::SerializableScalar;
use crate::{
    compute_lagrange_coefficient, Ciphersuite, CryptoRng, Error, Field, Group, Identifier, RngCore,
    Scalar,
};

use super::{generate_coefficients, SigningShare};

/// A delta value which is the output of part 1 of RTS.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "C: Ciphersuite"))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Delta<C: Ciphersuite>(pub(crate) SerializableScalar<C>);

impl<C> Delta<C>
where
    C: Ciphersuite,
{
    /// Create a new [`Delta`] from a scalar.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
    pub(crate) fn new(scalar: Scalar<C>) -> Self {
        Self(SerializableScalar(scalar))
    }

    /// Get the inner scalar.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
    pub(crate) fn to_scalar(&self) -> Scalar<C> {
        self.0 .0
    }

    /// Deserialize from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error<C>> {
        Ok(Self(SerializableScalar::deserialize(bytes)?))
    }

    /// Serialize to bytes
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize()
    }
}

/// A sigma value which is the output of part 2 of RTS.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "C: Ciphersuite"))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Sigma<C: Ciphersuite>(pub(crate) SerializableScalar<C>);

impl<C> Sigma<C>
where
    C: Ciphersuite,
{
    /// Create a new [`Sigma`] from a scalar.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
    pub(crate) fn new(scalar: Scalar<C>) -> Self {
        Self(SerializableScalar(scalar))
    }

    /// Get the inner scalar.
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
    pub(crate) fn to_scalar(&self) -> Scalar<C> {
        self.0 .0
    }

    /// Deserialize from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error<C>> {
        Ok(Self(SerializableScalar::deserialize(bytes)?))
    }

    /// Serialize to bytes
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize()
    }
}

/// Part 1 of RTS.
///
/// Generates the "delta" values from the helper with `key_package_i` to send to
/// `helpers` (which includes the helper with `key_package_i`), to help
/// `participant` recover their share.
///
/// Returns a BTreeMap mapping which value should be sent to which participant.
pub fn repair_share_part1<C: Ciphersuite, R: RngCore + CryptoRng>(
    helpers: &[Identifier<C>],
    key_package_i: &KeyPackage<C>,
    rng: &mut R,
    participant: Identifier<C>,
) -> Result<BTreeMap<Identifier<C>, Delta<C>>, Error<C>> {
    if helpers.len() < 2 {
        return Err(Error::IncorrectNumberOfIdentifiers);
    }
    if !helpers.contains(&key_package_i.identifier) {
        return Err(Error::UnknownIdentifier);
    }
    let xset: BTreeSet<_> = helpers.iter().cloned().collect();
    if xset.len() != helpers.len() {
        return Err(Error::DuplicatedIdentifier);
    }

    let rand_val: Vec<Scalar<C>> = generate_coefficients::<C, R>(helpers.len() - 1, rng);

    compute_last_random_value(&xset, key_package_i, &rand_val, participant)
}

/// Compute the last delta value given the (generated uniformly at random) remaining ones
/// since they all must add up to `zeta_i * share_i`.
///
/// Returns a BTreeMap mapping which value should be sent to which participant.
fn compute_last_random_value<C: Ciphersuite>(
    helpers: &BTreeSet<Identifier<C>>,
    key_package_i: &KeyPackage<C>,
    random_values: &Vec<Scalar<C>>,
    participant: Identifier<C>,
) -> Result<BTreeMap<Identifier<C>, Delta<C>>, Error<C>> {
    // Calculate Lagrange Coefficient for helper_i
    let zeta_i =
        compute_lagrange_coefficient(helpers, Some(participant), key_package_i.identifier)?;

    let lhs = zeta_i * key_package_i.signing_share.to_scalar();

    let mut out: BTreeMap<Identifier<C>, Delta<C>> = helpers
        .iter()
        .copied()
        .zip(random_values.iter().map(|v| Delta::new(*v)))
        .collect();

    let mut sum_i_deltas = <<C::Group as Group>::Field>::zero();

    for v in random_values {
        sum_i_deltas = sum_i_deltas + *v;
    }

    out.insert(
        *helpers.last().ok_or(Error::IncorrectNumberOfIdentifiers)?,
        Delta::new(lhs - sum_i_deltas),
    );

    Ok(out)
}

/// Part 2 of RTS.
///
/// Generates the "sigma" value from all `deltas` received from all helpers.
/// The "sigma" value must be sent to the participant repairing their share.
pub fn repair_share_part2<C: Ciphersuite>(deltas: &[Delta<C>]) -> Sigma<C> {
    let mut sigma_j = <<C::Group as Group>::Field>::zero();

    for d in deltas {
        sigma_j = sigma_j + d.to_scalar();
    }

    Sigma::new(sigma_j)
}

/// Part 3 of RTS.
///
/// The participant with the given `identifier` recovers their `KeyPackage`
/// with the "sigma" values received from all helpers and the `PublicKeyPackage`
/// of the group (which can be sent by any of the helpers).
///
/// Returns an error if the `min_signers` field is not set in the `PublicKeyPackage`.
/// This happens for `PublicKeyPackage`s created before the 3.0.0 release;
/// in that case, the user should set the `min_signers` field manually.
pub fn repair_share_part3<C: Ciphersuite>(
    sigmas: &[Sigma<C>],
    identifier: Identifier<C>,
    public_key_package: &PublicKeyPackage<C>,
) -> Result<KeyPackage<C>, Error<C>> {
    let mut share = <<C::Group as Group>::Field>::zero();

    for s in sigmas {
        share = share + s.to_scalar();
    }
    let signing_share = SigningShare::new(share);
    let verifying_share = signing_share.into();

    Ok(KeyPackage {
        header: Default::default(),
        identifier,
        signing_share,
        verifying_share,
        verifying_key: *public_key_package.verifying_key(),
        min_signers: public_key_package
            .min_signers()
            .ok_or(Error::InvalidMinSigners)?,
    })
}
