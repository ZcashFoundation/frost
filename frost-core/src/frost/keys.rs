//! FROST keys, keygen, key shares
#![allow(clippy::type_complexity)]

use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    default::Default,
    fmt::{self, Debug},
    iter,
};

use derive_getters::Getters;
#[cfg(any(test, feature = "test-impl"))]
use hex::FromHex;

use rand_core::{CryptoRng, RngCore};
use zeroize::{DefaultIsZeroes, Zeroize};

use crate::{
    frost::Identifier, Ciphersuite, Element, Error, Field, Group, Scalar, SigningKey, VerifyingKey,
};

#[cfg(feature = "serde")]
use crate::{ElementSerialization, ScalarSerialization};

pub mod dkg;
pub mod repairable;

/// Return a vector of randomly generated polynomial coefficients ([`Scalar`]s).
pub(crate) fn generate_coefficients<C: Ciphersuite, R: RngCore + CryptoRng>(
    size: usize,
    rng: &mut R,
) -> Vec<Scalar<C>> {
    iter::repeat_with(|| <<C::Group as Group>::Field>::random(rng))
        .take(size)
        .collect()
}

/// Return a list of default identifiers (1 to max_signers, inclusive).
pub(crate) fn default_identifiers<C: Ciphersuite>(max_signers: u16) -> Vec<Identifier<C>> {
    (1..=max_signers)
        .map(|i| Identifier::<C>::try_from(i).expect("nonzero"))
        .collect::<Vec<_>>()
}

/// A secret scalar value representing a signer's share of the group secret.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "ScalarSerialization<C>"))]
#[cfg_attr(feature = "serde", serde(into = "ScalarSerialization<C>"))]
pub struct SigningShare<C: Ciphersuite>(pub(crate) Scalar<C>);

impl<C> SigningShare<C>
where
    C: Ciphersuite,
{
    /// Deserialize from bytes
    pub fn from_bytes(
        bytes: <<C::Group as Group>::Field as Field>::Serialization,
    ) -> Result<Self, Error<C>> {
        <<C::Group as Group>::Field>::deserialize(&bytes)
            .map(|scalar| Self(scalar))
            .map_err(|e| e.into())
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> <<C::Group as Group>::Field as Field>::Serialization {
        <<C::Group as Group>::Field>::serialize(&self.0)
    }
}

impl<C> Debug for SigningShare<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SigningShare")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

impl<C> Default for SigningShare<C>
where
    C: Ciphersuite,
{
    fn default() -> Self {
        Self(<<C::Group as Group>::Field>::zero())
    }
}

// Implements [`Zeroize`] by overwriting a value with the [`Default::default()`] value
impl<C> DefaultIsZeroes for SigningShare<C> where C: Ciphersuite {}

#[cfg(any(test, feature = "test-impl"))]
impl<C> FromHex for SigningShare<C>
where
    C: Ciphersuite,
{
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let v: Vec<u8> = FromHex::from_hex(hex).map_err(|_| "invalid hex")?;
        match v.try_into() {
            Ok(bytes) => Self::from_bytes(bytes).map_err(|_| "malformed secret encoding"),
            Err(_) => Err("malformed secret encoding"),
        }
    }
}

#[cfg(feature = "serde")]
impl<C> TryFrom<ScalarSerialization<C>> for SigningShare<C>
where
    C: Ciphersuite,
{
    type Error = Error<C>;

    fn try_from(value: ScalarSerialization<C>) -> Result<Self, Self::Error> {
        Self::from_bytes(value.0)
    }
}

#[cfg(feature = "serde")]
impl<C> From<SigningShare<C>> for ScalarSerialization<C>
where
    C: Ciphersuite,
{
    fn from(value: SigningShare<C>) -> Self {
        Self(value.to_bytes())
    }
}

/// A public group element that represents a single signer's public verification share.
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "ElementSerialization<C>"))]
#[cfg_attr(feature = "serde", serde(into = "ElementSerialization<C>"))]
pub struct VerifyingShare<C>(pub(super) Element<C>)
where
    C: Ciphersuite;

impl<C> VerifyingShare<C>
where
    C: Ciphersuite,
{
    /// Deserialize from bytes
    pub fn from_bytes(bytes: <C::Group as Group>::Serialization) -> Result<Self, Error<C>> {
        <C::Group as Group>::deserialize(&bytes)
            .map(|element| Self(element))
            .map_err(|e| e.into())
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> <C::Group as Group>::Serialization {
        <C::Group as Group>::serialize(&self.0)
    }
}

impl<C> Debug for VerifyingShare<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("VerifyingShare")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

impl<C> From<SigningShare<C>> for VerifyingShare<C>
where
    C: Ciphersuite,
{
    fn from(secret: SigningShare<C>) -> VerifyingShare<C> {
        VerifyingShare(<C::Group>::generator() * secret.0 as Scalar<C>)
    }
}

#[cfg(feature = "serde")]
impl<C> TryFrom<ElementSerialization<C>> for VerifyingShare<C>
where
    C: Ciphersuite,
{
    type Error = Error<C>;

    fn try_from(value: ElementSerialization<C>) -> Result<Self, Self::Error> {
        Self::from_bytes(value.0)
    }
}

#[cfg(feature = "serde")]
impl<C> From<VerifyingShare<C>> for ElementSerialization<C>
where
    C: Ciphersuite,
{
    fn from(value: VerifyingShare<C>) -> Self {
        Self(value.to_bytes())
    }
}

/// A [`Group::Element`] newtype that is a commitment to one coefficient of our secret polynomial.
///
/// This is a (public) commitment to one coefficient of a secret polynomial used for performing
/// verifiable secret sharing for a Shamir secret share.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "ElementSerialization<C>"))]
#[cfg_attr(feature = "serde", serde(into = "ElementSerialization<C>"))]
pub struct CoefficientCommitment<C: Ciphersuite>(pub(crate) Element<C>);

impl<C> CoefficientCommitment<C>
where
    C: Ciphersuite,
{
    /// returns serialized element
    pub fn serialize(&self) -> <C::Group as Group>::Serialization {
        <C::Group>::serialize(&self.0)
    }

    /// Creates a new commitment from a coefficient input
    pub fn deserialize(
        coefficient: <C::Group as Group>::Serialization,
    ) -> Result<CoefficientCommitment<C>, Error<C>> {
        Ok(Self(<C::Group as Group>::deserialize(&coefficient)?))
    }

    /// Returns inner element value
    pub fn value(&self) -> Element<C> {
        self.0
    }
}

#[cfg(feature = "serde")]
impl<C> TryFrom<ElementSerialization<C>> for CoefficientCommitment<C>
where
    C: Ciphersuite,
{
    type Error = Error<C>;

    fn try_from(value: ElementSerialization<C>) -> Result<Self, Self::Error> {
        Self::deserialize(value.0)
    }
}

#[cfg(feature = "serde")]
impl<C> From<CoefficientCommitment<C>> for ElementSerialization<C>
where
    C: Ciphersuite,
{
    fn from(value: CoefficientCommitment<C>) -> Self {
        Self(value.serialize())
    }
}

/// Contains the commitments to the coefficients for our secret polynomial _f_,
/// used to generate participants' key shares.
///
/// [`VerifiableSecretSharingCommitment`] contains a set of commitments to the coefficients (which
/// themselves are scalars) for a secret polynomial f, where f is used to
/// generate each ith participant's key share f(i). Participants use this set of
/// commitments to perform verifiable secret sharing.
///
/// Note that participants MUST be assured that they have the *same*
/// [`VerifiableSecretSharingCommitment`], either by performing pairwise comparison, or by using
/// some agreed-upon public location for publication, where each participant can
/// ensure that they received the correct (and same) value.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerifiableSecretSharingCommitment<C: Ciphersuite>(
    pub(crate) Vec<CoefficientCommitment<C>>,
);

impl<C> VerifiableSecretSharingCommitment<C>
where
    C: Ciphersuite,
{
    /// Returns serialized coefficent commitments
    pub fn serialize(&self) -> Vec<<C::Group as Group>::Serialization> {
        self.0
            .iter()
            .map(|cc| <<C as Ciphersuite>::Group as Group>::serialize(&cc.0))
            .collect()
    }

    /// Returns VerifiableSecretSharingCommitment from a vector of serialized CoefficientCommitments
    pub fn deserialize(
        serialized_coefficient_commitments: Vec<<C::Group as Group>::Serialization>,
    ) -> Result<Self, Error<C>> {
        let mut coefficient_commitments = Vec::new();
        for cc in serialized_coefficient_commitments {
            coefficient_commitments.push(CoefficientCommitment::<C>::deserialize(cc)?);
        }

        Ok(Self(coefficient_commitments))
    }
}

/// A secret share generated by performing a (t-out-of-n) secret sharing scheme,
/// generated by a dealer performing [`generate_with_dealer`].
///
/// `n` is the total number of shares and `t` is the threshold required to reconstruct the secret;
/// in this case we use Shamir's secret sharing.
///
/// As a solution to the secret polynomial _f_ (a 'point'), the `identifier` is the x-coordinate, and the
/// `value` is the y-coordinate.
///
/// To derive a FROST keypair, the receiver of the [`SecretShare`] *must* call
/// .into(), which under the hood also performs validation.
#[derive(Clone, Zeroize, PartialEq, Eq, Getters)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct SecretShare<C: Ciphersuite> {
    /// The participant identifier of this [`SecretShare`].
    #[zeroize(skip)]
    pub(crate) identifier: Identifier<C>,
    /// Secret Key.
    pub(crate) value: SigningShare<C>,
    #[zeroize(skip)]
    /// The commitments to be distributed among signers.
    pub(crate) commitment: VerifiableSecretSharingCommitment<C>,
    /// Ciphersuite ID for serialization
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "crate::ciphersuite_serialize::<_, C>")
    )]
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "crate::ciphersuite_deserialize::<_, C>")
    )]
    #[getter(skip)]
    ciphersuite: (),
}

impl<C> SecretShare<C>
where
    C: Ciphersuite,
{
    /// Create a new [`SecretShare`] instance.
    pub fn new(
        identifier: Identifier<C>,
        value: SigningShare<C>,
        commitment: VerifiableSecretSharingCommitment<C>,
    ) -> Self {
        SecretShare {
            identifier,
            value,
            commitment,
            ciphersuite: (),
        }
    }

    /// Gets the inner [`SigningShare`] value.
    pub fn secret(&self) -> &SigningShare<C> {
        &self.value
    }

    /// Verifies that a secret share is consistent with a verifiable secret sharing commitment,
    /// and returns the derived group info for the participant (their public verification share,
    /// and the group public key) if successful.
    ///
    /// This ensures that this participant's share has been generated using the same
    /// mechanism as all other signing participants. Note that participants *MUST*
    /// ensure that they have the same view as all other participants of the
    /// commitment!
    ///
    /// An implementation of `vss_verify()` from the [spec].
    /// This also implements `derive_group_info()` from the [spec] (which is very similar),
    /// but only for this participant.
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#appendix-C.2-4
    pub fn verify(&self) -> Result<(VerifyingShare<C>, VerifyingKey<C>), Error<C>> {
        let f_result = <C::Group>::generator() * self.value.0;
        let result = evaluate_vss(&self.commitment, self.identifier);

        if !(f_result == result) {
            return Err(Error::InvalidSecretShare);
        }

        let group_public = VerifyingKey {
            element: self.commitment.0[0].0,
        };

        Ok((VerifyingShare(result), group_public))
    }
}

/// The identifier list to use when generating key shares.
pub enum IdentifierList<'a, C: Ciphersuite> {
    /// Use the default values (1 to max_signers, inclusive).
    Default,
    /// A user-provided list of identifiers.
    Custom(&'a [Identifier<C>]),
}

/// Allows all participants' keys to be generated using a central, trusted
/// dealer.
///
/// Under the hood, this performs verifiable secret sharing, which itself uses
/// Shamir secret sharing, from which each share becomes a participant's secret
/// key. The output from this function is a set of shares along with one single
/// commitment that participants use to verify the integrity of the share. The
/// number of signers is limited to 255.
///
/// Implements [`trusted_dealer_keygen`] from the spec.
///
/// [`trusted_dealer_keygen`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#appendix-C
pub fn generate_with_dealer<C: Ciphersuite, R: RngCore + CryptoRng>(
    max_signers: u16,
    min_signers: u16,
    identifiers: IdentifierList<C>,
    rng: &mut R,
) -> Result<(HashMap<Identifier<C>, SecretShare<C>>, PublicKeyPackage<C>), Error<C>> {
    let mut bytes = [0; 64];
    rng.fill_bytes(&mut bytes);

    let key = SigningKey::new(rng);

    split(&key, max_signers, min_signers, identifiers, rng)
}

/// Splits an existing key into FROST shares.
///
/// This is identical to [`generate_with_dealer`] but receives an existing key
/// instead of generating a fresh one. This is useful in scenarios where
/// the key needs to be generated externally or must be derived from e.g. a
/// seed phrase.
pub fn split<C: Ciphersuite, R: RngCore + CryptoRng>(
    key: &SigningKey<C>,
    max_signers: u16,
    min_signers: u16,
    identifiers: IdentifierList<C>,
    rng: &mut R,
) -> Result<(HashMap<Identifier<C>, SecretShare<C>>, PublicKeyPackage<C>), Error<C>> {
    let group_public = VerifyingKey::from(key);

    let coefficients = generate_coefficients::<C, R>(min_signers as usize - 1, rng);

    let default_identifiers = default_identifiers(max_signers);
    let identifiers = match identifiers {
        IdentifierList::Custom(identifiers) => identifiers,
        IdentifierList::Default => &default_identifiers,
    };

    let secret_shares =
        generate_secret_shares(key, max_signers, min_signers, coefficients, identifiers)?;
    let mut signer_pubkeys: HashMap<Identifier<C>, VerifyingShare<C>> =
        HashMap::with_capacity(max_signers as usize);

    let mut secret_shares_by_id: HashMap<Identifier<C>, SecretShare<C>> =
        HashMap::with_capacity(max_signers as usize);

    for secret_share in secret_shares {
        let signer_public = secret_share.value.into();
        signer_pubkeys.insert(secret_share.identifier, signer_public);

        secret_shares_by_id.insert(secret_share.identifier, secret_share);
    }

    Ok((
        secret_shares_by_id,
        PublicKeyPackage {
            signer_pubkeys,
            group_public,
            ciphersuite: (),
        },
    ))
}

/// Evaluate the polynomial with the given coefficients (constant term first)
/// at the point x=identifier using Horner's method.
///
/// Implements [`polynomial_evaluate`] from the spec.
///
/// [`polynomial_evaluate`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#name-evaluation-of-a-polynomial
fn evaluate_polynomial<C: Ciphersuite>(
    identifier: Identifier<C>,
    coefficients: &[Scalar<C>],
) -> Scalar<C> {
    let mut value = <<C::Group as Group>::Field>::zero();

    let ell_scalar = identifier;
    for coeff in coefficients.iter().skip(1).rev() {
        value = value + *coeff;
        value *= ell_scalar;
    }
    value = value + coefficients[0];
    value
}

/// Evaluates the right-hand side of the VSS verification equation, namely
/// ∏^{t−1}_{k=0} φ^{i^k mod q}_{ℓk} using `identifier` as `i` and the
/// `commitment` as the commitment vector φ_ℓ
fn evaluate_vss<C: Ciphersuite>(
    commitment: &VerifiableSecretSharingCommitment<C>,
    identifier: Identifier<C>,
) -> Element<C> {
    let i = identifier;

    let (_, result) = commitment.0.iter().fold(
        (<<C::Group as Group>::Field>::one(), <C::Group>::identity()),
        |(i_to_the_k, sum_so_far), comm_k| (i * i_to_the_k, sum_so_far + comm_k.0 * i_to_the_k),
    );
    result
}

/// A FROST keypair, which can be generated either by a trusted dealer or using
/// a DKG.
///
/// When using a central dealer, [`SecretShare`]s are distributed to
/// participants, who then perform verification, before deriving
/// [`KeyPackage`]s, which they store to later use during signing.
#[derive(Clone, PartialEq, Eq, Getters)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct KeyPackage<C: Ciphersuite> {
    /// Denotes the participant identifier each secret share key package is owned by.
    pub(crate) identifier: Identifier<C>,
    /// This participant's secret share.
    pub(crate) secret_share: SigningShare<C>,
    /// This participant's public key.
    pub(crate) public: VerifyingShare<C>,
    /// The public signing key that represents the entire group.
    pub(crate) group_public: VerifyingKey<C>,
    /// Ciphersuite ID for serialization
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "crate::ciphersuite_serialize::<_, C>")
    )]
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "crate::ciphersuite_deserialize::<_, C>")
    )]
    #[getter(skip)]
    ciphersuite: (),
}

impl<C> KeyPackage<C>
where
    C: Ciphersuite,
{
    /// Create a new [`KeyPackage`] instance.
    pub fn new(
        identifier: Identifier<C>,
        secret_share: SigningShare<C>,
        public: VerifyingShare<C>,
        group_public: VerifyingKey<C>,
    ) -> Self {
        Self {
            identifier,
            secret_share,
            public,
            group_public,
            ciphersuite: (),
        }
    }
}

impl<C> TryFrom<SecretShare<C>> for KeyPackage<C>
where
    C: Ciphersuite,
{
    type Error = Error<C>;

    /// Tries to verify a share and construct a [`KeyPackage`] from it.
    ///
    /// When participants receive a [`SecretShare`] from the dealer, they
    /// *MUST* verify the integrity of the share before continuing on to
    /// transform it into a signing/verification keypair. Here, we assume that
    /// every participant has the same view of the commitment issued by the
    /// dealer, but implementations *MUST* make sure that all participants have
    /// a consistent view of this commitment in practice.
    fn try_from(secret_share: SecretShare<C>) -> Result<Self, Error<C>> {
        let (public, group_public) = secret_share.verify()?;

        Ok(KeyPackage {
            identifier: secret_share.identifier,
            secret_share: secret_share.value,
            public,
            group_public,
            ciphersuite: (),
        })
    }
}

/// Public data that contains all the signers' public keys as well as the
/// group public key.
///
/// Used for verification purposes before publishing a signature.
#[derive(Clone, PartialEq, Eq, Getters)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct PublicKeyPackage<C: Ciphersuite> {
    /// When performing signing, the coordinator must ensure that they have the
    /// correct view of participants' public keys to perform verification before
    /// publishing a signature. `signer_pubkeys` represents all signers for a
    /// signing operation.
    pub(crate) signer_pubkeys: HashMap<Identifier<C>, VerifyingShare<C>>,
    /// The joint public key for the entire group.
    pub(crate) group_public: VerifyingKey<C>,
    /// Ciphersuite ID for serialization
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "crate::ciphersuite_serialize::<_, C>")
    )]
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "crate::ciphersuite_deserialize::<_, C>")
    )]
    #[getter(skip)]
    ciphersuite: (),
}

impl<C> PublicKeyPackage<C>
where
    C: Ciphersuite,
{
    /// Create a new [`PublicKeyPackage`] instance.
    pub fn new(
        signer_pubkeys: HashMap<Identifier<C>, VerifyingShare<C>>,
        group_public: VerifyingKey<C>,
    ) -> Self {
        Self {
            signer_pubkeys,
            group_public,
            ciphersuite: (),
        }
    }
}

/// Generate a secret polynomial to use in secret sharing, for the given
/// secret value. Also validates the given parameters.
///
/// Returns the full vector of coefficients in little-endian order (including the
/// given secret, which is the first element) and a [`VerifiableSecretSharingCommitment`]
/// which contains commitments to those coefficients.
///
/// Returns an error if the parameters (max_signers, min_signers) are inconsistent.
pub(crate) fn generate_secret_polynomial<C: Ciphersuite>(
    secret: &SigningKey<C>,
    max_signers: u16,
    min_signers: u16,
    mut coefficients: Vec<Scalar<C>>,
) -> Result<(Vec<Scalar<C>>, VerifiableSecretSharingCommitment<C>), Error<C>> {
    if min_signers < 2 {
        return Err(Error::InvalidMinSigners);
    }

    if max_signers < 2 {
        return Err(Error::InvalidMaxSigners);
    }

    if min_signers > max_signers {
        return Err(Error::InvalidMinSigners);
    }

    if coefficients.len() != min_signers as usize - 1 {
        return Err(Error::InvalidCoefficients);
    }

    // Prepend the secret, which is the 0th coefficient
    coefficients.insert(0, secret.scalar);

    // Create the vector of commitments
    let commitment: Vec<_> = coefficients
        .iter()
        .map(|c| CoefficientCommitment(<C::Group as Group>::generator() * *c))
        .collect();
    let commitment: VerifiableSecretSharingCommitment<C> =
        VerifiableSecretSharingCommitment(commitment);

    Ok((coefficients, commitment))
}

/// Creates secret shares for a given secret using the given coefficients.
///
/// This function accepts a secret from which shares are generated,
/// and a list of threshold-1 coefficients. While in FROST this secret
/// and coefficients should always be generated randomly, we allow them
/// to be specified for this internal function for testability.
///
/// Internally, [`generate_secret_shares`] performs verifiable secret sharing, which
/// generates shares via Shamir Secret Sharing, and then generates public
/// commitments to those shares.
///
/// More specifically, [`generate_secret_shares`]:
/// - Interpret [secret, `coefficients[0]`, ...] as a secret polynomial f
/// - For each participant i, their secret share is f(i)
/// - The commitment to the secret polynomial f is [g^secret, `g^coefficients[0]`, ...]
///
/// Implements [`secret_share_shard`] from the spec.
///
/// [`secret_share_shard`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#appendix-C.1
pub(crate) fn generate_secret_shares<C: Ciphersuite>(
    secret: &SigningKey<C>,
    max_signers: u16,
    min_signers: u16,
    coefficients: Vec<Scalar<C>>,
    identifiers: &[Identifier<C>],
) -> Result<Vec<SecretShare<C>>, Error<C>> {
    let mut secret_shares: Vec<SecretShare<C>> = Vec::with_capacity(max_signers as usize);

    let (coefficients, commitment) =
        generate_secret_polynomial(secret, max_signers, min_signers, coefficients)?;

    let identifiers_set: HashSet<_> = identifiers.iter().collect();
    if identifiers_set.len() != identifiers.len() {
        return Err(Error::DuplicatedIdentifier);
    }

    for id in identifiers {
        let value = evaluate_polynomial(*id, &coefficients);

        secret_shares.push(SecretShare {
            identifier: *id,
            value: SigningShare(value),
            commitment: commitment.clone(),
            ciphersuite: (),
        });
    }

    Ok(secret_shares)
}

/// Recompute the secret from at least `min_signers` secret shares
/// using Lagrange interpolation.
///
/// This can be used if for some reason the original key must be restored; e.g.
/// if threshold signing is not required anymore.
///
/// This is NOT required to sign with FROST; the point of FROST is being
/// able to generate signatures only using the shares, without having to
/// reconstruct the original key.
///
/// The caller is responsible for providing at least `min_signers` shares;
/// if less than that is provided, a different key will be returned.
pub fn reconstruct<C: Ciphersuite>(
    secret_shares: &[SecretShare<C>],
) -> Result<SigningKey<C>, Error<C>> {
    if secret_shares.is_empty() {
        return Err(Error::IncorrectNumberOfShares);
    }

    let mut secret = <<C::Group as Group>::Field>::zero();

    // Compute the Lagrange coefficients
    for (i_idx, i, secret_share) in secret_shares
        .iter()
        .enumerate()
        .map(|(idx, s)| (idx, s.identifier, s))
    {
        let mut num = <<C::Group as Group>::Field>::one();
        let mut den = <<C::Group as Group>::Field>::one();

        for (j_idx, j) in secret_shares
            .iter()
            .enumerate()
            .map(|(idx, s)| (idx, s.identifier))
        {
            if j_idx == i_idx {
                continue;
            }

            // numerator *= j
            num *= j;

            // denominator *= j - i
            den *= j - i;
        }

        // If at this step, the denominator is zero in the scalar field, there must be a duplicate
        // secret share.
        if den == <<C::Group as Group>::Field>::zero() {
            return Err(Error::DuplicatedShares);
        }

        // Save numerator * 1/denominator in the scalar field
        let lagrange_coefficient = num * <<C::Group as Group>::Field>::invert(&den).unwrap();

        // Compute y = f(0) via polynomial interpolation of these t-of-n solutions ('points) of f
        secret = secret + (lagrange_coefficient * secret_share.value.0);
    }

    Ok(SigningKey { scalar: secret })
}
