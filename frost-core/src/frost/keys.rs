//! FROST keys, keygen, key shares

use std::{
    collections::HashMap,
    convert::TryFrom,
    default::Default,
    fmt::{self, Debug},
};

use hex::FromHex;
use rand_core::{CryptoRng, RngCore};
use zeroize::{DefaultIsZeroes, Zeroize};

use crate::{frost::Identifier, Ciphersuite, Error, Field, Group, Scalar, VerifyingKey};

/// A secret scalar value representing a signer's secret key.
#[derive(Clone, Copy, PartialEq)]
pub struct Secret<C: Ciphersuite>(pub(crate) Scalar<C>);

impl<C> Secret<C>
where
    C: Ciphersuite,
{
    /// Deserialize [`Secret`] from bytes
    pub fn from_bytes(
        bytes: <<C::Group as Group>::Field as Field>::Serialization,
    ) -> Result<Self, Error> {
        <<C::Group as Group>::Field as Field>::deserialize(&bytes).map(|scalar| Self(scalar))
    }

    /// Serialize [`Secret`] to bytes
    pub fn to_bytes(&self) -> <<C::Group as Group>::Field as Field>::Serialization {
        <<C::Group as Group>::Field as Field>::serialize(&self.0)
    }

    /// Generates a new uniformly random secret value using the provided RNG.
    // TODO: should this only be behind test?
    pub fn random<R>(mut rng: R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        Self(<<C::Group as Group>::Field as Field>::random_nonzero(
            &mut rng,
        ))
    }
}

impl<C> Debug for Secret<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Secret")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

impl<C> Default for Secret<C>
where
    C: Ciphersuite,
{
    fn default() -> Self {
        Self(<<C::Group as Group>::Field as Field>::zero())
    }
}

// Implements [`Zeroize`] by overwriting a value with the [`Default::default()`] value
impl<C> DefaultIsZeroes for Secret<C> where C: Ciphersuite {}

// impl<C> Drop for Secret<C>
// where
//     C: Ciphersuite,
// {
//     fn drop(&mut self) {
//         self.zeroize()
//     }
// }

impl<C> From<&Secret<C>> for VerifyingKey<C>
where
    C: Ciphersuite,
{
    fn from(secret: &Secret<C>) -> Self {
        let element = <C::Group as Group>::generator() * secret.0;

        VerifyingKey { element }
    }
}

impl<C> FromHex for Secret<C>
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

/// A public group element that represents a single signer's public key.
#[derive(Copy, Clone, PartialEq)]
pub struct Public<C>(pub(super) <C::Group as Group>::Element)
where
    C: Ciphersuite;

impl<C> Public<C>
where
    C: Ciphersuite,
{
    /// Deserialize from bytes
    pub fn from_bytes(bytes: <C::Group as Group>::Serialization) -> Result<Self, Error> {
        <C::Group as Group>::deserialize(&bytes).map(|element| Self(element))
    }

    /// Serialize [`Public`] to bytes
    pub fn to_bytes(&self) -> <C::Group as Group>::Serialization {
        <C::Group as Group>::serialize(&self.0)
    }
}

impl<C> Debug for Public<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Public")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

impl<C> From<Secret<C>> for Public<C>
where
    C: Ciphersuite,
{
    fn from(secret: Secret<C>) -> Public<C> {
        Public(<C::Group as Group>::generator() * secret.0 as Scalar<C>)
    }
}

/// A [`Group::Element`] that is a commitment to one coefficient of our secret polynomial.
///
/// This is a (public) commitment to one coefficient of a secret polynomial used for performing
/// verifiable secret sharing for a Shamir secret share.
#[derive(Clone, Copy, PartialEq)]
pub(super) struct CoefficientCommitment<C: Ciphersuite>(pub(super) <C::Group as Group>::Element);

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
#[derive(Clone)]
pub struct VerifiableSecretSharingCommitment<C: Ciphersuite>(
    pub(super) Vec<CoefficientCommitment<C>>,
);

/// A secret share generated by performing a (t-out-of-n) secret sharing scheme.
///
/// `n` is the total number of shares and `t` is the threshold required to reconstruct the secret;
/// in this case we use Shamir's secret sharing.
///
/// As a solution to the secret polynomial _f_ (a 'point'), the `index` is the x-coordinate, and the
/// `value` is the y-coordinate.
#[derive(Clone, Zeroize)]
pub struct SecretShare<C: Ciphersuite> {
    /// The participant index of this [`SecretShare`].
    pub index: u16,
    /// Secret Key.
    pub value: Secret<C>,
    /// The commitments to be distributed among signers.
    pub commitment: VerifiableSecretSharingCommitment<C>,
}

impl<C> SecretShare<C>
where
    C: Ciphersuite,
{
    /// Gets the inner [`Secret`] share value.
    pub fn secret(&self) -> &Secret<C> {
        &self.value
    }

    /// Verifies that a secret share is consistent with a verifiable secret sharing commitment.
    ///
    /// This ensures that this participant's share has been generated using the same
    /// mechanism as all other signing participants. Note that participants *MUST*
    /// ensure that they have the same view as all other participants of the
    /// commitment!
    ///
    /// An implementation of `vss_verify()` from the [spec].
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-05.html#appendix-B.2-5
    pub fn verify(&self) -> Result<(), &'static str> {
        let f_result = <C::Group as Group>::generator() * self.value.0;

        let x = Identifier::<C>::try_from(self.index).unwrap();

        let (_, result) = self.commitment.0.iter().fold(
            (
                <<C::Group as Group>::Field as Field>::one(),
                <C::Group as Group>::identity(),
            ),
            |(x_to_the_i, sum_so_far), comm_i| {
                (*x * x_to_the_i, sum_so_far + comm_i.0 * x_to_the_i)
            },
        );

        if !(f_result == result) {
            return Err("SecretShare is invalid.");
        }

        Ok(())
    }
}

/// Secret and public key material generated by a dealer performing
/// [`keygen_with_dealer`].
///
/// To derive a FROST keypair, the receiver of the [`SharePackage`] *must* call
/// .into(), which under the hood also performs validation.
#[derive(Clone)]
pub struct SharePackage<C: Ciphersuite> {
    /// Denotes the participant index each share is owned by.
    pub index: u16,
    /// This participant's secret share.
    pub secret_share: SecretShare<C>,
    /// This participant's public key.
    pub public: Public<C>,
    /// The public signing key that represents the entire group.
    pub group_public: VerifyingKey<C>,
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
/// [`trusted_dealer_keygen`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-03.html#appendix-B
pub fn keygen_with_dealer<C: Ciphersuite, R: RngCore + CryptoRng>(
    num_signers: u8,
    threshold: u8,
    mut rng: R,
) -> Result<(Vec<SharePackage<C>>, PublicKeyPackage<C>), &'static str> {
    let mut bytes = [0; 64];
    rng.fill_bytes(&mut bytes);

    let secret = Secret::random(&mut rng);
    let group_public = VerifyingKey::from(&secret);
    let secret_shares = generate_secret_shares(&secret, num_signers, threshold, rng)?;
    let mut share_packages: Vec<SharePackage<C>> = Vec::with_capacity(num_signers as usize);
    let mut signer_pubkeys: HashMap<u16, Public<C>> = HashMap::with_capacity(num_signers as usize);

    for secret_share in secret_shares {
        let signer_public = secret_share.value.into();

        share_packages.push(SharePackage {
            index: secret_share.index,
            secret_share: secret_share.clone(),
            public: signer_public,
            group_public,
        });

        signer_pubkeys.insert(secret_share.index, signer_public);
    }

    Ok((
        share_packages,
        PublicKeyPackage {
            signer_pubkeys,
            group_public,
        },
    ))
}

/// A FROST keypair, which can be generated either by a trusted dealer or using
/// a DKG.
///
/// When using a central dealer, [`SharePackage`]s are distributed to
/// participants, who then perform verification, before deriving
/// [`KeyPackage`]s, which they store to later use during signing.
#[derive(Clone)]
pub struct KeyPackage<C: Ciphersuite> {
    /// Denotes the participant index each secret share key package is owned by.
    pub index: u16,
    /// This participant's secret share.
    pub secret_share: Secret<C>,
    /// This participant's public key.
    pub public: Public<C>,
    /// The public signing key that represents the entire group.
    pub group_public: VerifyingKey<C>,
}

impl<C> KeyPackage<C>
where
    C: Ciphersuite,
{
    /// Gets the participant index associated with this [`KeyPackage`].
    pub fn index(&self) -> &u16 {
        &self.index
    }

    /// Gets the participant's [`Secret`] share associated with this [`KeyPackage`].
    pub fn secret_share(&self) -> &Secret<C> {
        &self.secret_share
    }

    /// Gets the participant's [`Public`] key  associated with this [`Secret`] share in this [`KeyPackage`].
    pub fn public(&self) -> &Public<C> {
        &self.public
    }

    /// Gets the group [`VerifyingKey`] associated with the entire group in this [`KeyPackage`].
    pub fn group_public(&self) -> &VerifyingKey<C> {
        &self.group_public
    }
}

impl<C> TryFrom<SharePackage<C>> for KeyPackage<C>
where
    C: Ciphersuite,
{
    type Error = &'static str;

    /// Tries to verify a share and construct a [`KeyPackage`] from it.
    ///
    /// When participants receive a [`SharePackage`] from the dealer, they
    /// *MUST* verify the integrity of the share before continuing on to
    /// transform it into a signing/verification keypair. Here, we assume that
    /// every participant has the same view of the commitment issued by the
    /// dealer, but implementations *MUST* make sure that all participants have
    /// a consistent view of this commitment in practice.
    fn try_from(share_package: SharePackage<C>) -> Result<Self, &'static str> {
        share_package.secret_share.verify()?;

        Ok(KeyPackage {
            index: share_package.index,
            secret_share: share_package.secret_share.value,
            public: share_package.public,
            group_public: share_package.group_public,
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
    pub signer_pubkeys: HashMap<u16, Public<C>>,
    /// The joint public key for the entire group.
    pub group_public: VerifyingKey<C>,
}

/// Creates secret shares for a given secret.
///
/// This function accepts a secret from which shares are generated. While in
/// FROST this secret should always be generated randomly, we allow this secret
/// to be specified for this internal function for testability.
///
/// Internally, [`generate_secret_shares`] performs verifiable secret sharing, which
/// generates shares via Shamir Secret Sharing, and then generates public
/// commitments to those shares.
///
/// More specifically, [`generate_secret_shares`]:
/// - Randomly samples of coefficients [a, b, c], this represents a secret
/// polynomial f
/// - For each participant i, their secret share is f(i)
/// - The commitment to the secret polynomial f is [g^a, g^b, g^c]
///
/// Implements [`secret_key_shard`] from the spec.
///
/// [`secret_key_shard`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-03.html#appendix-B.1
pub fn generate_secret_shares<C: Ciphersuite, R: RngCore + CryptoRng>(
    secret: &Secret<C>,
    numshares: u8,
    threshold: u8,
    mut rng: R,
) -> Result<Vec<SecretShare<C>>, &'static str> {
    if threshold < 2 {
        return Err("Threshold cannot be less than 2");
    }

    if numshares < 2 {
        return Err("Number of shares cannot be less than the minimum threshold 2");
    }

    if threshold > numshares {
        return Err("Threshold cannot exceed numshares");
    }

    let numcoeffs = threshold - 1;

    let mut coefficients: Vec<Scalar<C>> = Vec::with_capacity(threshold as usize);

    let mut secret_shares: Vec<SecretShare<C>> = Vec::with_capacity(numshares as usize);

    let mut commitment: VerifiableSecretSharingCommitment<C> =
        VerifiableSecretSharingCommitment(Vec::with_capacity(threshold as usize));

    for _ in 0..numcoeffs {
        coefficients.push(<<C::Group as Group>::Field as Field>::random(&mut rng));
    }

    // Verifiable secret sharing, to make sure that participants can ensure their
    // secret is consistent with every other participant's.
    commitment.0.push(CoefficientCommitment(
        <C::Group as Group>::generator() * secret.0,
    ));

    for c in &coefficients {
        commitment
            .0
            .push(CoefficientCommitment(<C::Group as Group>::generator() * *c));
    }

    // Evaluate the polynomial with `secret` as the constant term
    // and `coeffs` as the other coefficients at the point x=share_index,
    // using Horner's method.
    for id in (1..=numshares as u16).map_while(|i| Identifier::<C>::try_from(i).ok()) {
        let mut value = <<C::Group as Group>::Field as Field>::zero();

        // Polynomial evaluation, for this index
        //
        // We rely only on `Add` and `Mul` here so as to not require `AddAssign` and `MulAssign`
        //
        // Note that this is from the 'last' coefficient to the 'first'.
        for i in (0..numcoeffs).rev() {
            value = value + coefficients[i as usize];
            value = *id * value;
        }
        value = value + secret.0;

        secret_shares.push(SecretShare {
            index: usize::from(id) as u16,
            value: Secret(value),
            commitment: commitment.clone(),
        });
    }

    Ok(secret_shares)
}

/// Recompute the secret from t-of-n secret shares using Lagrange interpolation.
pub fn reconstruct_secret<C: Ciphersuite>(
    secret_shares: Vec<SecretShare<C>>,
) -> Result<Secret<C>, &'static str> {
    if secret_shares.is_empty() {
        return Err("No secret_shares provided");
    }

    let secret_share_map: HashMap<Identifier<C>, SecretShare<C>> = secret_shares
        .into_iter()
        .map(|share| (Identifier::<C>::try_from(share.index).unwrap(), share))
        .collect();

    let mut secret = <<C::Group as Group>::Field as Field>::zero();

    // Compute the Lagrange coefficients
    for (i, secret_share) in secret_share_map.clone() {
        let mut num = <<C::Group as Group>::Field as Field>::one();
        let mut den = <<C::Group as Group>::Field as Field>::one();

        for j in secret_share_map.clone().into_keys() {
            if j == i {
                continue;
            }

            // numerator *= j
            num = num * *j;

            // denominator *= j - i
            den = den * (*j - *i);
        }

        // If at this step, the denominator is zero in the scalar field, there must be a duplicate
        // secret share.
        if den == <<C::Group as Group>::Field as Field>::zero() {
            return Err("Duplicate shares provided");
        }

        // Save numerator * 1/denomintor in the scalar field
        let lagrange_coefficient =
            num * <<C::Group as Group>::Field as Field>::invert(&den).unwrap();

        // Compute y = f(0) via polynomial interpolation of these t-of-n solutions ('points) of f
        secret = secret + (lagrange_coefficient * secret_share.value.0);
    }

    Ok(Secret::from_bytes(<<C::Group as Group>::Field as Field>::serialize(&secret)).unwrap())
}
