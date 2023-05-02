//! FROST keys, keygen, key shares
#![allow(clippy::type_complexity)]

use std::{
    collections::HashMap,
    convert::TryFrom,
    default::Default,
    fmt::{self, Debug},
    iter,
};

#[cfg(any(test, feature = "test-impl"))]
use hex::FromHex;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{DefaultIsZeroes, Zeroize};

use crate::{
    frost::Identifier, random_nonzero, Ciphersuite, Element, Error, Field, Group, Scalar,
    VerifyingKey,
};

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

/// A group secret to be split between participants.
///
/// This is similar to a [`crate::SigningKey`], but this secret is not intended to be used
/// on its own for signing, but split into shares that a threshold number of signers will use to
/// sign.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SharedSecret<C: Ciphersuite>(pub(crate) Scalar<C>);

impl<C> SharedSecret<C>
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

    /// Generates a new uniformly random secret value using the provided RNG.
    // TODO: should this only be behind test?
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        Self(random_nonzero::<C, R>(rng))
    }
}

impl<C> Debug for SharedSecret<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SharedSecret")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

impl<C> Default for SharedSecret<C>
where
    C: Ciphersuite,
{
    fn default() -> Self {
        Self(<<C::Group as Group>::Field>::zero())
    }
}

// Implements [`Zeroize`] by overwriting a value with the [`Default::default()`] value
impl<C> DefaultIsZeroes for SharedSecret<C> where C: Ciphersuite {}

impl<C> From<&SharedSecret<C>> for VerifyingKey<C>
where
    C: Ciphersuite,
{
    fn from(secret: &SharedSecret<C>) -> Self {
        let element = <C::Group>::generator() * secret.0;

        VerifyingKey { element }
    }
}

#[cfg(any(test, feature = "test-impl"))]
impl<C> FromHex for SharedSecret<C>
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

/// A secret scalar value representing a signer's share of the group secret.
#[derive(Clone, Copy, PartialEq, Eq)]
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

impl<C> serde::Serialize for SigningShare<C>
where
    C: Ciphersuite,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.to_bytes().as_ref())
    }
}

impl<'de, C> serde::Deserialize<'de> for SigningShare<C>
where
    C: Ciphersuite,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let array = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid byte length"))?;
        let identifier =
            Self::from_bytes(array).map_err(|err| serde::de::Error::custom(format!("{err}")))?;
        Ok(identifier)
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

/// A public group element that represents a single signer's public verification share.
#[derive(Copy, Clone, PartialEq, Eq)]
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

/// A [`Group::Element`] newtype that is a commitment to one coefficient of our secret polynomial.
///
/// This is a (public) commitment to one coefficient of a secret polynomial used for performing
/// verifiable secret sharing for a Shamir secret share.
#[derive(Clone, Copy, PartialEq)]
pub(super) struct CoefficientCommitment<C: Ciphersuite>(pub(super) Element<C>);

impl<C> serde::Serialize for CoefficientCommitment<C>
where
    C: Ciphersuite,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = <C::Group as Group>::serialize(&self.0);
        serializer.serialize_bytes(bytes.as_ref())
    }
}

impl<'de, C> serde::Deserialize<'de> for CoefficientCommitment<C>
where
    C: Ciphersuite,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let array = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid byte length"))?;
        let element = <C::Group as Group>::deserialize(&array)
            .map_err(|err| serde::de::Error::custom(format!("{err}")))?;
        Ok(Self(element))
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
#[derive(Clone, Deserialize, Serialize)]
pub struct VerifiableSecretSharingCommitment<C: Ciphersuite>(
    pub(super) Vec<CoefficientCommitment<C>>,
);

/// A secret share generated by performing a (t-out-of-n) secret sharing scheme,
/// generated by a dealer performing [`keygen_with_dealer`].
///
/// `n` is the total number of shares and `t` is the threshold required to reconstruct the secret;
/// in this case we use Shamir's secret sharing.
///
/// As a solution to the secret polynomial _f_ (a 'point'), the `identifier` is the x-coordinate, and the
/// `value` is the y-coordinate.
///
/// To derive a FROST keypair, the receiver of the [`SecretShare`] *must* call
/// .into(), which under the hood also performs validation.
#[derive(Clone, Zeroize)]
pub struct SecretShare<C: Ciphersuite> {
    /// The participant identifier of this [`SecretShare`].
    #[zeroize(skip)]
    pub identifier: Identifier<C>,
    /// Secret Key.
    pub value: SigningShare<C>,
    #[zeroize(skip)]
    /// The commitments to be distributed among signers.
    pub commitment: VerifiableSecretSharingCommitment<C>,
}

impl<C> SecretShare<C>
where
    C: Ciphersuite,
{
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
pub fn keygen_with_dealer<C: Ciphersuite, R: RngCore + CryptoRng>(
    max_signers: u16,
    min_signers: u16,
    rng: &mut R,
) -> Result<(HashMap<Identifier<C>, SecretShare<C>>, PublicKeyPackage<C>), Error<C>> {
    let mut bytes = [0; 64];
    rng.fill_bytes(&mut bytes);

    let secret = SharedSecret::random(rng);
    let group_public = VerifyingKey::from(&secret);

    let coefficients = generate_coefficients::<C, R>(min_signers as usize - 1, rng);

    let secret_shares = generate_secret_shares(&secret, max_signers, min_signers, coefficients)?;
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
#[derive(Clone)]
pub struct KeyPackage<C: Ciphersuite> {
    /// Denotes the participant identifier each secret share key package is owned by.
    pub identifier: Identifier<C>,
    /// This participant's secret share.
    pub secret_share: SigningShare<C>,
    /// This participant's public key.
    pub public: VerifyingShare<C>,
    /// The public signing key that represents the entire group.
    pub group_public: VerifyingKey<C>,
}

impl<C> KeyPackage<C>
where
    C: Ciphersuite,
{
    /// Gets the participant identifier associated with this [`KeyPackage`].
    pub fn identifier(&self) -> &Identifier<C> {
        &self.identifier
    }

    /// Gets the participant's [`SigningShare`] associated with this [`KeyPackage`].
    pub fn secret_share(&self) -> &SigningShare<C> {
        &self.secret_share
    }

    /// Gets the participant's [`VerifyingShare`] associated with the [`SigningShare`] in this [`KeyPackage`].
    pub fn public(&self) -> &VerifyingShare<C> {
        &self.public
    }

    /// Gets the group [`VerifyingKey`] associated with the entire group in this [`KeyPackage`].
    pub fn group_public(&self) -> &VerifyingKey<C> {
        &self.group_public
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
        })
    }
}

/// Public data that contains all the signers' public keys as well as the
/// group public key.
///
/// Used for verification purposes before publishing a signature.
pub struct PublicKeyPackage<C: Ciphersuite> {
    /// When performing signing, the coordinator must ensure that they have the
    /// correct view of participants' public keys to perform verification before
    /// publishing a signature. `signer_pubkeys` represents all signers for a
    /// signing operation.
    pub signer_pubkeys: HashMap<Identifier<C>, VerifyingShare<C>>,
    /// The joint public key for the entire group.
    pub group_public: VerifyingKey<C>,
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
    secret: &SharedSecret<C>,
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
    coefficients.insert(0, secret.0);

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
    secret: &SharedSecret<C>,
    max_signers: u16,
    min_signers: u16,
    coefficients: Vec<Scalar<C>>,
) -> Result<Vec<SecretShare<C>>, Error<C>> {
    let mut secret_shares: Vec<SecretShare<C>> = Vec::with_capacity(max_signers as usize);

    let (coefficients, commitment) =
        generate_secret_polynomial(secret, max_signers, min_signers, coefficients)?;

    for idx in 1..=max_signers {
        let id = Identifier::<C>::try_from(idx)?;
        let value = evaluate_polynomial(id, &coefficients);

        secret_shares.push(SecretShare {
            identifier: id,
            value: SigningShare(value),
            commitment: commitment.clone(),
        });
    }

    Ok(secret_shares)
}

/// Recompute the secret from t-of-n secret shares using Lagrange interpolation.
pub fn reconstruct_secret<C: Ciphersuite>(
    secret_shares: Vec<SecretShare<C>>,
) -> Result<SharedSecret<C>, &'static str> {
    if secret_shares.is_empty() {
        return Err("No secret_shares provided");
    }

    let secret_share_map: HashMap<Identifier<C>, SecretShare<C>> = secret_shares
        .into_iter()
        .map(|share| (share.identifier, share))
        .collect();

    let mut secret = <<C::Group as Group>::Field>::zero();

    // Compute the Lagrange coefficients
    for (i, secret_share) in secret_share_map.clone() {
        let mut num = <<C::Group as Group>::Field>::one();
        let mut den = <<C::Group as Group>::Field>::one();

        for j in secret_share_map.clone().into_keys() {
            if j == i {
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
            return Err("Duplicate shares provided");
        }

        // Save numerator * 1/denomintor in the scalar field
        let lagrange_coefficient = num * <<C::Group as Group>::Field>::invert(&den).unwrap();

        // Compute y = f(0) via polynomial interpolation of these t-of-n solutions ('points) of f
        secret = secret + (lagrange_coefficient * secret_share.value.0);
    }

    Ok(SharedSecret::from_bytes(<<C::Group as Group>::Field>::serialize(&secret)).unwrap())
}
