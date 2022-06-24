//! FROST Round 1 functionality and types

use std::fmt::{self, Debug};

use hex::FromHex;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::{frost, Ciphersuite, Error, Field, Group};

/// A scalar that is a signing nonce.
#[derive(Clone, PartialEq, Zeroize)]
pub struct Nonce<C: Ciphersuite>(pub(super) <<C::Group as Group>::Field as Field>::Scalar);

impl<C> Nonce<C>
where
    C: Ciphersuite,
{
    /// Generates a new uniformly random signing nonce.
    ///
    /// Each participant generates signing nonces before performing a signing
    /// operation.
    ///
    /// An implementation of `RandomNonzeroScalar()` from the [spec].
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.html#section-3.1-3.4
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        // The values of 'hiding' and 'binding' nonces must be non-zero so that commitments are
        // not the identity.
        Self(<<C::Group as Group>::Field as Field>::random_nonzero(rng))
    }

    /// Deserialize [`Nonce`] from bytes
    pub fn from_bytes(
        bytes: <<C::Group as Group>::Field as Field>::Serialization,
    ) -> Result<Self, Error> {
        <<C::Group as Group>::Field as Field>::deserialize(&bytes).map(|scalar| Self(scalar))
    }

    /// Serialize [`Nonce`] to bytes
    pub fn to_bytes(&self) -> <<C::Group as Group>::Field as Field>::Serialization {
        <<C::Group as Group>::Field as Field>::serialize(&self.0)
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
pub struct NonceCommitment<C: Ciphersuite>(pub(super) <C::Group as Group>::Element);

impl<C> NonceCommitment<C>
where
    C: Ciphersuite,
{
    /// Deserialize [`NonceCommitment`] from bytes
    pub fn from_bytes(bytes: <C::Group as Group>::Serialization) -> Result<Self, Error> {
        <C::Group as Group>::deserialize(&bytes).map(|element| Self(element))
    }

    /// Serialize [`NonceCommitment`] to bytes
    pub fn to_bytes(&self) -> <C::Group as Group>::Serialization {
        <C::Group as Group>::serialize(&self.0)
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
        Self(<C::Group as Group>::generator() * nonce.0)
    }
}

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
    pub fn new<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        // The values of 'hiding' and 'binding' must be non-zero so that commitments are
        // not the identity.
        let hiding = Nonce::<C>::random(rng);
        let binding = Nonce::<C>::random(rng);

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
#[derive(Copy, Clone)]
pub struct SigningCommitments<C: Ciphersuite> {
    /// The participant index.
    pub index: u16,
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
    /// [signature commitment share]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-03.html#name-signature-share-verificatio
    pub(super) fn to_group_commitment_share(
        self,
        binding_factor: &frost::Rho<C>,
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

impl<C> From<(u16, &SigningNonces<C>)> for SigningCommitments<C>
where
    C: Ciphersuite,
{
    fn from((index, nonces): (u16, &SigningNonces<C>)) -> Self {
        Self {
            index,
            hiding: nonces.hiding.clone().into(),
            binding: nonces.binding.clone().into(),
        }
    }
}

/// One signer's share of the group commitment, derived from their individual signing commitments
/// and the binding factor _rho_.
#[derive(Clone, Copy, PartialEq)]
pub struct GroupCommitmentShare<C: Ciphersuite>(pub(super) <C::Group as Group>::Element);

/// Encode the list of group signing commitments.
///
/// Implements [`encode_group_commitment_list()`] from the spec.
///
/// Inputs:
/// - commitment_list = [(j, D_j, E_j), ...], a list of commitments issued by each signer,
///   where each element in the list indicates the signer index and their
///   two commitment Element values. B MUST be sorted in ascending order
///   by signer index.
///
/// Outputs:
/// - A byte string containing the serialized representation of B.
///
/// [`encode_group_commitment_list()`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-03.html#section-4.3
pub(super) fn encode_group_commitments<C: Ciphersuite>(
    signing_commitments: Vec<SigningCommitments<C>>,
) -> Vec<u8> {
    // B MUST be sorted in ascending order by signer index.
    //
    // https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#encoding-operations-dep-encoding
    //
    // TODO: AtLeastOne or other explicitly Sorted wrapper types?
    let mut sorted_signing_commitments = signing_commitments;
    sorted_signing_commitments.sort_by_key(|a| a.index);

    let mut bytes = vec![];

    for item in sorted_signing_commitments {
        bytes.extend_from_slice(&item.index.to_be_bytes()); // TODO: 2-bytes until spec moves off u16
        bytes.extend_from_slice(<C::Group as Group>::serialize(&item.hiding.0).as_ref());
        bytes.extend_from_slice(<C::Group as Group>::serialize(&item.binding.0).as_ref());
    }

    bytes
}

/// Done once by each participant, to generate _their_ nonces and commitments
/// that are then used during signing.
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
    participant_index: u16,
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
        let nonces = SigningNonces::new(rng);
        signing_commitments.push(SigningCommitments::from((participant_index, &nonces)));
        signing_nonces.push(nonces);
    }

    (signing_nonces, signing_commitments)
}
