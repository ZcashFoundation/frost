//! FROST Round 1 functionality and types

use std::{
    collections::BTreeMap,
    fmt::{self, Debug},
};

use derive_getters::Getters;
#[cfg(any(test, feature = "test-impl"))]
use hex::FromHex;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate as frost;
use crate::{
    serialization::{Deserialize, Serialize},
    Ciphersuite, Element, Error, Field, Group, Header, Scalar,
};

#[cfg(feature = "serde")]
use crate::serialization::{ElementSerialization, ScalarSerialization};

use super::{keys::SigningShare, Identifier};

/// A scalar that is a signing nonce.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "C: Ciphersuite"))]
#[cfg_attr(feature = "serde", serde(try_from = "ScalarSerialization<C>"))]
#[cfg_attr(feature = "serde", serde(into = "ScalarSerialization<C>"))]
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
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-nonce-generation
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
    pub fn deserialize(
        bytes: <<C::Group as Group>::Field as Field>::Serialization,
    ) -> Result<Self, Error<C>> {
        <<C::Group as Group>::Field>::deserialize(&bytes)
            .map(|scalar| Self(scalar))
            .map_err(|e| e.into())
    }

    /// Serialize [`Nonce`] to bytes
    pub fn serialize(&self) -> <<C::Group as Group>::Field as Field>::Serialization {
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

#[cfg(any(test, feature = "test-impl"))]
impl<C> FromHex for Nonce<C>
where
    C: Ciphersuite,
{
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let v: Vec<u8> = FromHex::from_hex(hex).map_err(|_| "invalid hex")?;
        match v.try_into() {
            Ok(bytes) => Self::deserialize(bytes).map_err(|_| "malformed nonce encoding"),
            Err(_) => Err("malformed nonce encoding"),
        }
    }
}

#[cfg(feature = "serde")]
impl<C> TryFrom<ScalarSerialization<C>> for Nonce<C>
where
    C: Ciphersuite,
{
    type Error = Error<C>;

    fn try_from(value: ScalarSerialization<C>) -> Result<Self, Self::Error> {
        Self::deserialize(value.0)
    }
}

#[cfg(feature = "serde")]
impl<C> From<Nonce<C>> for ScalarSerialization<C>
where
    C: Ciphersuite,
{
    fn from(value: Nonce<C>) -> Self {
        Self(value.serialize())
    }
}

/// A group element that is a commitment to a signing nonce share.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "C: Ciphersuite"))]
#[cfg_attr(feature = "serde", serde(try_from = "ElementSerialization<C>"))]
#[cfg_attr(feature = "serde", serde(into = "ElementSerialization<C>"))]
pub struct NonceCommitment<C: Ciphersuite>(pub(super) Element<C>);

impl<C> NonceCommitment<C>
where
    C: Ciphersuite,
{
    /// Deserialize [`NonceCommitment`] from bytes
    pub fn deserialize(bytes: <C::Group as Group>::Serialization) -> Result<Self, Error<C>> {
        <C::Group>::deserialize(&bytes)
            .map(|element| Self(element))
            .map_err(|e| e.into())
    }

    /// Serialize [`NonceCommitment`] to bytes
    pub fn serialize(&self) -> <C::Group as Group>::Serialization {
        <C::Group>::serialize(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<C> TryFrom<ElementSerialization<C>> for NonceCommitment<C>
where
    C: Ciphersuite,
{
    type Error = Error<C>;

    fn try_from(value: ElementSerialization<C>) -> Result<Self, Self::Error> {
        Self::deserialize(value.0)
    }
}

#[cfg(feature = "serde")]
impl<C> From<NonceCommitment<C>> for ElementSerialization<C>
where
    C: Ciphersuite,
{
    fn from(value: NonceCommitment<C>) -> Self {
        Self(value.serialize())
    }
}

impl<C> Debug for NonceCommitment<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("NonceCommitment")
            .field(&hex::encode(self.serialize()))
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
            Ok(bytes) => {
                Self::deserialize(bytes).map_err(|_| "malformed nonce commitment encoding")
            }
            Err(_) => Err("malformed nonce commitment encoding"),
        }
    }
}

/// Comprised of hiding and binding nonces.
///
/// Note that [`SigningNonces`] must be used *only once* for a signing
/// operation; re-using nonces will result in leakage of a signer's long-lived
/// signing key.
#[derive(Clone, Zeroize, PartialEq, Eq, Getters)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "C: Ciphersuite"))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct SigningNonces<C: Ciphersuite> {
    /// Serialization header
    #[getter(skip)]
    pub(crate) header: Header<C>,
    /// The hiding [`Nonce`].
    pub(crate) hiding: Nonce<C>,
    /// The binding [`Nonce`].
    pub(crate) binding: Nonce<C>,
    /// The commitments to the nonces. This is precomputed to improve
    /// sign() performance, since it needs to check if the commitments
    /// to the participant's nonces are included in the commitments sent
    /// by the Coordinator, and this prevents having to recompute them.
    #[zeroize(skip)]
    pub(crate) commitments: SigningCommitments<C>,
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
        let hiding = Nonce::<C>::new(secret, rng);
        let binding = Nonce::<C>::new(secret, rng);

        Self::from_nonces(hiding, binding)
    }

    /// Generates a new [`SigningNonces`] from a pair of [`Nonce`].
    ///
    /// # Security
    ///
    /// SigningNonces MUST NOT be repeated in different FROST signings.
    /// Thus, if you're using this method (because e.g. you're writing it
    /// to disk between rounds), be careful so that does not happen.
    pub fn from_nonces(hiding: Nonce<C>, binding: Nonce<C>) -> Self {
        let hiding_commitment = (&hiding).into();
        let binding_commitment = (&binding).into();
        let commitments = SigningCommitments::new(hiding_commitment, binding_commitment);

        Self {
            header: Header::default(),
            hiding,
            binding,
            commitments,
        }
    }
}

impl<C> Debug for SigningNonces<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningNonces")
            .field("hiding", &"<redacted>")
            .field("binding", &"<redacted>")
            .finish()
    }
}

#[cfg(feature = "serialization")]
impl<C> SigningNonces<C>
where
    C: Ciphersuite,
{
    /// Serialize the struct into a Vec.
    pub fn serialize(&self) -> Result<Vec<u8>, Error<C>> {
        Serialize::serialize(&self)
    }

    /// Deserialize the struct from a slice of bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error<C>> {
        Deserialize::deserialize(bytes)
    }
}

/// Published by each participant in the first round of the signing protocol.
///
/// This step can be batched if desired by the implementation. Each
/// SigningCommitment can be used for exactly *one* signature.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Getters)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "C: Ciphersuite"))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct SigningCommitments<C: Ciphersuite> {
    /// Serialization header
    #[getter(skip)]
    pub(crate) header: Header<C>,
    /// Commitment to the hiding [`Nonce`].
    pub(crate) hiding: NonceCommitment<C>,
    /// Commitment to the binding [`Nonce`].
    pub(crate) binding: NonceCommitment<C>,
}

impl<C> SigningCommitments<C>
where
    C: Ciphersuite,
{
    /// Create new SigningCommitments
    pub fn new(hiding: NonceCommitment<C>, binding: NonceCommitment<C>) -> Self {
        Self {
            header: Header::default(),
            hiding,
            binding,
        }
    }

    /// Computes the [signature commitment share] from these round one signing commitments.
    ///
    /// [signature commitment share]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-signature-share-verificatio
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
    pub(super) fn to_group_commitment_share(
        self,
        binding_factor: &frost::BindingFactor<C>,
    ) -> GroupCommitmentShare<C> {
        GroupCommitmentShare::<C>(self.hiding.0 + (self.binding.0 * binding_factor.0))
    }
}

#[cfg(feature = "serialization")]
impl<C> SigningCommitments<C>
where
    C: Ciphersuite,
{
    /// Serialize the struct into a Vec.
    pub fn serialize(&self) -> Result<Vec<u8>, Error<C>> {
        Serialize::serialize(&self)
    }

    /// Deserialize the struct from a slice of bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error<C>> {
        Deserialize::deserialize(bytes)
    }
}

impl<C> From<&SigningNonces<C>> for SigningCommitments<C>
where
    C: Ciphersuite,
{
    fn from(nonces: &SigningNonces<C>) -> Self {
        nonces.commitments
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
/// `signing_commitments` must contain the sorted map of participants
/// identifiers to the signing commitments they issued.
///
/// Returns a byte string containing the serialized representation of the
/// commitment list.
///
/// [`encode_group_commitment_list()`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-list-operations
pub(super) fn encode_group_commitments<C: Ciphersuite>(
    signing_commitments: &BTreeMap<Identifier<C>, SigningCommitments<C>>,
) -> Vec<u8> {
    let mut bytes = vec![];

    for (item_identifier, item) in signing_commitments {
        bytes.extend_from_slice(item_identifier.serialize().as_ref());
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
pub fn preprocess<C, R>(
    num_nonces: u8,
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
        signing_commitments.push(SigningCommitments::from(&nonces));
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
/// [`commit`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-round-one-commitment
pub fn commit<C, R>(
    secret: &SigningShare<C>,
    rng: &mut R,
) -> (SigningNonces<C>, SigningCommitments<C>)
where
    C: Ciphersuite,
    R: CryptoRng + RngCore,
{
    let (mut vec_signing_nonces, mut vec_signing_commitments) = preprocess(1, secret, rng);
    (
        vec_signing_nonces.pop().expect("must have 1 element"),
        vec_signing_commitments.pop().expect("must have 1 element"),
    )
}
