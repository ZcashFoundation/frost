//! FROST Round 1 functionality and types

use std::fmt::{self, Debug};

#[cfg(any(test, feature = "test-impl"))]
use hex::FromHex;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{frost, Ciphersuite, Element, Error, Field, Group, Scalar};

use super::{keys::SigningShare, Identifier};

/// A scalar that is a signing nonce.
#[derive(Clone, PartialEq, Eq)]
pub struct Nonce<C: Ciphersuite>(pub(super) Scalar<C>);

impl<C> Nonce<C>
where
    C: Ciphersuite,
{
    /// Generates a new uniformly random signing nonce by sourcing fresh randomness and combining
    /// with the secret signing share, to hedge against a bad RNG.
    ///
    /// Each participant generates signing nonces before performing a signing
    /// operation.
    ///
    /// An implementation of `nonce_generate(secret)` from the [spec].
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#name-nonce-generation
    pub fn new<R>(secret: &SigningShare<C>, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let mut random_bytes = [0; 32];
        rng.fill_bytes(&mut random_bytes[..]);

        Self::nonce_generate_from_random_bytes(secret, random_bytes)
    }

    /// Generates a nonce from the given random bytes.
    /// This function allows testing and MUST NOT be made public.
    pub(crate) fn nonce_generate_from_random_bytes(
        secret: &SigningShare<C>,
        random_bytes: [u8; 32],
    ) -> Self {
        let secret_enc = <<C::Group as Group>::Field>::serialize(&secret.0);

        let input: Vec<u8> = random_bytes
            .iter()
            .chain(secret_enc.as_ref().iter())
            .cloned()
            .collect();

        Self(C::H3(input.as_slice()))
    }

    /// Deserialize [`Nonce`] from bytes
    pub fn from_bytes(
        bytes: <<C::Group as Group>::Field as Field>::Serialization,
    ) -> Result<Self, Error<C>> {
        <<C::Group as Group>::Field>::deserialize(&bytes)
            .map(|scalar| Self(scalar))
            .map_err(|e| e.into())
    }

    /// Serialize [`Nonce`] to bytes
    pub fn to_bytes(&self) -> <<C::Group as Group>::Field as Field>::Serialization {
        <<C::Group as Group>::Field>::serialize(&self.0)
    }
}

impl<C> Zeroize for Nonce<C>
where
    C: Ciphersuite,
{
    fn zeroize(&mut self) {
        *self = Nonce(<<C::Group as Group>::Field>::zero());
    }
}

// impl<C> Drop for Nonce<C>
// where
//     C: Ciphersuite,
// {
//     fn drop(&mut self) {
//         self.zeroize()
//     }
// }

#[cfg(any(test, feature = "test-impl"))]
impl<C> FromHex for Nonce<C>
where
    C: Ciphersuite,
{
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let v: Vec<u8> = FromHex::from_hex(hex).map_err(|_| "invalid hex")?;
        match v.try_into() {
            Ok(bytes) => Self::from_bytes(bytes).map_err(|_| "malformed nonce encoding"),
            Err(_) => Err("malformed nonce encoding"),
        }
    }
}

/// A Ristretto point that is a commitment to a signing nonce share.
#[derive(Clone, Copy, PartialEq)]
pub struct NonceCommitment<C: Ciphersuite>(pub(super) Element<C>);

impl<C> NonceCommitment<C>
where
    C: Ciphersuite,
{
    /// Deserialize [`NonceCommitment`] from bytes
    pub fn from_bytes(bytes: <C::Group as Group>::Serialization) -> Result<Self, Error<C>> {
        <C::Group>::deserialize(&bytes)
            .map(|element| Self(element))
            .map_err(|e| e.into())
    }

    /// Serialize [`NonceCommitment`] to bytes
    pub fn to_bytes(&self) -> <C::Group as Group>::Serialization {
        <C::Group>::serialize(&self.0)
    }
}

impl<C> serde::Serialize for NonceCommitment<C>
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

impl<'de, C> serde::Deserialize<'de> for NonceCommitment<C>
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

impl<C> Debug for NonceCommitment<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("NonceCommitment")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

impl<C> From<Nonce<C>> for NonceCommitment<C>
where
    C: Ciphersuite,
{
    fn from(nonce: Nonce<C>) -> Self {
        From::from(&nonce)
    }
}

impl<C> From<&Nonce<C>> for NonceCommitment<C>
where
    C: Ciphersuite,
{
    fn from(nonce: &Nonce<C>) -> Self {
        Self(<C::Group>::generator() * nonce.0)
    }
}

#[cfg(any(test, feature = "test-impl"))]
impl<C> FromHex for NonceCommitment<C>
where
    C: Ciphersuite,
{
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let v: Vec<u8> = FromHex::from_hex(hex).map_err(|_| "invalid hex")?;
        match v.try_into() {
            Ok(bytes) => Self::from_bytes(bytes).map_err(|_| "malformed nonce commitment encoding"),
            Err(_) => Err("malformed nonce commitment encoding"),
        }
    }
}

/// Comprised of hiding and binding nonces.
///
/// Note that [`SigningNonces`] must be used *only once* for a signing
/// operation; re-using nonces will result in leakage of a signer's long-lived
/// signing key.
#[derive(Clone, Zeroize)]
pub struct SigningNonces<C: Ciphersuite> {
    /// The hiding [`Nonce`].
    pub hiding: Nonce<C>,
    /// The binding [`Nonce`].
    pub binding: Nonce<C>,
}

impl<C> SigningNonces<C>
where
    C: Ciphersuite,
{
    /// Generates a new signing nonce.
    ///
    /// Each participant generates signing nonces before performing a signing
    /// operation.
    pub fn new<R>(secret: &SigningShare<C>, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        // The values of 'hiding' and 'binding' must be non-zero so that commitments are
        // not the identity.
        let hiding = Nonce::<C>::new(secret, rng);
        let binding = Nonce::<C>::new(secret, rng);

        Self { hiding, binding }
    }

    /// Gets the hiding [`Nonce`]
    pub fn hiding(&self) -> &Nonce<C> {
        &self.hiding
    }

    /// Gets the binding [`Nonce`]
    pub fn binding(&self) -> &Nonce<C> {
        &self.binding
    }
}

/// Published by each participant in the first round of the signing protocol.
///
/// This step can be batched if desired by the implementation. Each
/// SigningCommitment can be used for exactly *one* signature.
#[derive(Copy, Clone, Deserialize, Serialize)]
pub struct SigningCommitments<C: Ciphersuite> {
    /// The participant identifier.
    pub identifier: Identifier<C>,
    /// Commitment to the hiding [`Nonce`].
    pub hiding: NonceCommitment<C>,
    /// Commitment to the binding [`Nonce`].
    pub binding: NonceCommitment<C>,
}

impl<C> SigningCommitments<C>
where
    C: Ciphersuite,
{
    /// Computes the [signature commitment share] from these round one signing commitments.
    ///
    /// [signature commitment share]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#name-signature-share-verificatio
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    pub(super) fn to_group_commitment_share(
        self,
        binding_factor: &frost::BindingFactor<C>,
    ) -> GroupCommitmentShare<C> {
        GroupCommitmentShare::<C>(self.hiding.0 + (self.binding.0 * binding_factor.0))
    }

    /// Gets the hiding [`NonceCommitment`].
    pub fn hiding(&self) -> &NonceCommitment<C> {
        &self.hiding
    }

    /// Gets the binding [`NonceCommitment`].
    pub fn binding(&self) -> &NonceCommitment<C> {
        &self.binding
    }
}

impl<C> From<(Identifier<C>, &SigningNonces<C>)> for SigningCommitments<C>
where
    C: Ciphersuite,
{
    fn from((identifier, nonces): (Identifier<C>, &SigningNonces<C>)) -> Self {
        Self {
            identifier,
            hiding: nonces.hiding.clone().into(),
            binding: nonces.binding.clone().into(),
        }
    }
}

/// One signer's share of the group commitment, derived from their individual signing commitments
/// and the binding factor _rho_.
#[derive(Clone, Copy, PartialEq)]
pub struct GroupCommitmentShare<C: Ciphersuite>(pub(super) Element<C>);

/// Encode the list of group signing commitments.
///
/// Implements [`encode_group_commitment_list()`] from the spec.
///
/// Inputs:
/// - commitment_list = [(j, D_j, E_j), ...], a list of commitments issued by each signer,
///   where each element in the list indicates the signer identifier and their
///   two commitment Element values. B MUST be sorted in ascending order
///   by signer identifier.
///
/// Outputs:
/// - A byte string containing the serialized representation of B.
///
/// [`encode_group_commitment_list()`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#name-list-operations
pub(super) fn encode_group_commitments<C: Ciphersuite>(
    signing_commitments: Vec<SigningCommitments<C>>,
) -> Vec<u8> {
    // B MUST be sorted in ascending order by signer identifier.
    //
    // TODO: AtLeastOne or other explicitly Sorted wrapper types?
    let mut sorted_signing_commitments = signing_commitments;
    sorted_signing_commitments.sort_by_key(|a| a.identifier);

    let mut bytes = vec![];

    for item in sorted_signing_commitments {
        bytes.extend_from_slice(item.identifier.serialize().as_ref());
        bytes.extend_from_slice(<C::Group>::serialize(&item.hiding.0).as_ref());
        bytes.extend_from_slice(<C::Group>::serialize(&item.binding.0).as_ref());
    }

    bytes
}

/// Done once by each participant, to generate _their_ nonces and commitments
/// that are then used during signing.
///
/// This is only needed if pre-processing is needed (for 1-round FROST). For
/// regular 2-round FROST, use [`commit`].
///
/// When performing signing using two rounds, num_nonces would equal 1, to
/// perform the first round. Batching entails generating more than one
/// nonce/commitment pair at a time.  Nonces should be stored in secret storage
/// for later use, whereas the commitments are published.
///
/// The number of nonces is limited to 255. This limit can be increased if it
/// turns out to be too conservative.
// TODO: Make sure the above is a correct statement, fix if needed in:
// https://github.com/ZcashFoundation/redjubjub/issues/111
pub fn preprocess<C, R>(
    num_nonces: u8,
    participant_identifier: Identifier<C>,
    secret: &SigningShare<C>,
    rng: &mut R,
) -> (Vec<SigningNonces<C>>, Vec<SigningCommitments<C>>)
where
    C: Ciphersuite,
    R: CryptoRng + RngCore,
{
    let mut signing_nonces: Vec<SigningNonces<C>> = Vec::with_capacity(num_nonces as usize);
    let mut signing_commitments: Vec<SigningCommitments<C>> =
        Vec::with_capacity(num_nonces as usize);

    for _ in 0..num_nonces {
        let nonces = SigningNonces::new(secret, rng);
        signing_commitments.push(SigningCommitments::from((participant_identifier, &nonces)));
        signing_nonces.push(nonces);
    }

    (signing_nonces, signing_commitments)
}

/// Performed once by each participant selected for the signing operation.
///
/// Implements [`commit`] from the spec.
///
/// Generates the signing nonces and commitments to be used in the signing
/// operation.
///
/// [`commit`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#name-round-one-commitment
pub fn commit<C, R>(
    participant_identifier: Identifier<C>,
    secret: &SigningShare<C>,
    rng: &mut R,
) -> (SigningNonces<C>, SigningCommitments<C>)
where
    C: Ciphersuite,
    R: CryptoRng + RngCore,
{
    let (mut vec_signing_nonces, mut vec_signing_commitments) =
        preprocess(1, participant_identifier, secret, rng);
    (
        vec_signing_nonces.pop().expect("must have 1 element"),
        vec_signing_commitments.pop().expect("must have 1 element"),
    )
}
