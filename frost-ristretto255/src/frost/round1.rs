//! FROST Round 1 functionality and types

use std::{
    convert::TryFrom,
    fmt::{self, Debug},
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use hex::FromHex;
use rand_core::{CryptoRng, RngCore};
use zeroize::DefaultIsZeroes;

use crate::frost;

/// A scalar used in Ristretto that is a signing nonce.
#[derive(Clone, Copy, Default, PartialEq)]
pub(super) struct Nonce(pub(super) Scalar);

impl Nonce {
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
        loop {
            let scalar = Scalar::random(rng);
            if scalar != Scalar::zero() {
                return Self(scalar);
            }
        }
    }
}

impl AsRef<Scalar> for Nonce {
    fn as_ref(&self) -> &Scalar {
        &self.0
    }
}

impl Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Nonce")
            .field(&hex::encode(self.0.to_bytes()))
            .finish()
    }
}

// Zeroizes `Secret` to be the `Default` value on drop (when it goes out of scope).  Luckily the
// derived `Default` includes the `Default` impl of Scalar, which is four 0u64's under the hood.
impl DefaultIsZeroes for Nonce {}

impl FromHex for Nonce {
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 32];

        match hex::decode_to_slice(hex, &mut bytes[..]) {
            Ok(()) => Self::try_from(bytes),
            Err(_) => Err("invalid hex"),
        }
    }
}

impl TryFrom<[u8; 32]> for Nonce {
    type Error = &'static str;

    fn try_from(source: [u8; 32]) -> Result<Self, &'static str> {
        match Scalar::from_canonical_bytes(source) {
            Some(scalar) if scalar != Scalar::zero() => Ok(Self(scalar)),
            None => Err("ristretto scalar not canonical byte representation"),
            _ => Err("invalid nonce value"),
        }
    }
}

/// A Ristretto point that is a commitment to a signing nonce share.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct NonceCommitment(pub(super) RistrettoPoint);

impl From<Nonce> for NonceCommitment {
    fn from(nonce: Nonce) -> Self {
        Self(RISTRETTO_BASEPOINT_POINT * nonce.0)
    }
}

impl FromHex for NonceCommitment {
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 32];

        match hex::decode_to_slice(hex, &mut bytes[..]) {
            Ok(()) => Self::try_from(bytes),
            Err(_) => Err("invalid hex"),
        }
    }
}

impl TryFrom<[u8; 32]> for NonceCommitment {
    type Error = &'static str;

    fn try_from(source: [u8; 32]) -> Result<Self, &'static str> {
        match CompressedRistretto::from_slice(&source[..]).decompress() {
            Some(point) => Ok(Self(point)),
            None => Err("ristretto point was not canonically encoded"),
        }
    }
}

/// Comprised of hiding and binding nonces.
///
/// Note that [`SigningNonces`] must be used *only once* for a signing
/// operation; re-using nonces will result in leakage of a signer's long-lived
/// signing key.
#[derive(Clone, Copy, Default, Debug)]
pub struct SigningNonces {
    pub(super) hiding: Nonce,
    pub(super) binding: Nonce,
}

// Zeroizes `SigningNonces` to be the `Default` value on drop (when it goes out of scope).  Luckily
// the derived `Default` includes the `Default` impl of the `curve25519_dalek::scalar::Scalar`s,
// which is 32 0u8's under the hood.
impl DefaultIsZeroes for SigningNonces {}

impl SigningNonces {
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
        let hiding = Nonce::random(rng);
        let binding = Nonce::random(rng);

        Self { hiding, binding }
    }
}

/// Published by each participant in the first round of the signing protocol.
///
/// This step can be batched if desired by the implementation. Each
/// SigningCommitment can be used for exactly *one* signature.
#[derive(Copy, Clone, Debug)]
pub struct SigningCommitments {
    /// The participant index
    pub(super) index: u16,
    /// The hiding point.
    pub(super) hiding: NonceCommitment,
    /// The binding point.
    pub(super) binding: NonceCommitment,
}

impl SigningCommitments {
    /// Computes the [signature commitment share] from these round one signing commitments.
    ///
    /// [signature commitment share]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-03.html#name-signature-share-verificatio
    pub(super) fn to_group_commitment_share(
        self,
        binding_factor: &frost::Rho,
    ) -> GroupCommitmentShare {
        GroupCommitmentShare(self.hiding.0 + (self.binding.0 * binding_factor.0))
    }
}

impl From<(u16, &SigningNonces)> for SigningCommitments {
    fn from((index, nonces): (u16, &SigningNonces)) -> Self {
        Self {
            index,
            hiding: nonces.hiding.into(),
            binding: nonces.binding.into(),
        }
    }
}

/// One signer's share of the group commitment, derived from their individual signing commitments
/// and the binding factor _rho_.
#[derive(Clone, Copy, Default, PartialEq)]
pub struct GroupCommitmentShare(pub(super) RistrettoPoint);

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
pub(super) fn encode_group_commitments(signing_commitments: Vec<SigningCommitments>) -> Vec<u8> {
    // B MUST be sorted in ascending order by signer index.
    //
    // https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#encoding-operations-dep-encoding
    let mut sorted_signing_commitments = signing_commitments;
    sorted_signing_commitments.sort_by_key(|a| a.index);

    let mut bytes = vec![];

    for item in sorted_signing_commitments {
        bytes.extend_from_slice(&item.index.to_be_bytes()[..]);
        bytes.extend_from_slice(&item.hiding.0.compress().to_bytes()[..]);
        bytes.extend_from_slice(&item.binding.0.compress().to_bytes()[..]);
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
pub fn preprocess<R>(
    num_nonces: u8,
    participant_index: u16,
    rng: &mut R,
) -> (Vec<SigningNonces>, Vec<SigningCommitments>)
where
    R: CryptoRng + RngCore,
{
    let mut signing_nonces: Vec<SigningNonces> = Vec::with_capacity(num_nonces as usize);
    let mut signing_commitments: Vec<SigningCommitments> = Vec::with_capacity(num_nonces as usize);

    for _ in 0..num_nonces {
        let nonces = SigningNonces::new(rng);
        signing_commitments.push(SigningCommitments::from((participant_index, &nonces)));
        signing_nonces.push(nonces);
    }

    (signing_nonces, signing_commitments)
}
