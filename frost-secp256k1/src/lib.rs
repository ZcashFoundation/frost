#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc = document_features::document_features!()]

extern crate alloc;

use alloc::collections::BTreeMap;

use frost_rerandomized::RandomizedCiphersuite;
use k256::{
    elliptic_curve::{
        group::prime::PrimeCurveAffine,
        hash2curve::{hash_to_field, ExpandMsgXmd},
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field as FFField, PrimeField,
    },
    AffinePoint, ProjectivePoint, Scalar,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use frost_core as frost;

#[cfg(test)]
mod tests;

// Re-exports in our public API
#[cfg(feature = "serde")]
pub use frost_core::serde;
pub use frost_core::{Ciphersuite, Field, FieldError, Group, GroupError};
pub use rand_core;

/// An error.
pub type Error = frost_core::Error<Secp256K1Sha256>;

/// An implementation of the FROST(secp256k1, SHA-256) ciphersuite scalar field.
#[derive(Clone, Copy)]
pub struct Secp256K1ScalarField;

impl Field for Secp256K1ScalarField {
    type Scalar = Scalar;

    type Serialization = [u8; 32];

    fn zero() -> Self::Scalar {
        Scalar::ZERO
    }

    fn one() -> Self::Scalar {
        Scalar::ONE
    }

    fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, FieldError> {
        // [`Scalar`]'s Eq/PartialEq does a constant-time comparison
        if *scalar == <Self as Field>::zero() {
            Err(FieldError::InvalidZeroScalar)
        } else {
            Ok(scalar.invert().unwrap())
        }
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Scalar::random(rng)
    }

    fn serialize(scalar: &Self::Scalar) -> Self::Serialization {
        scalar.to_bytes().into()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, FieldError> {
        let field_bytes: &k256::FieldBytes = buf.into();
        match Scalar::from_repr(*field_bytes).into() {
            Some(s) => Ok(s),
            None => Err(FieldError::MalformedScalar),
        }
    }

    fn little_endian_serialize(scalar: &Self::Scalar) -> Self::Serialization {
        let mut array = Self::serialize(scalar);
        array.reverse();
        array
    }
}

/// An implementation of the FROST(secp256k1, SHA-256) ciphersuite group.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Secp256K1Group;

impl Group for Secp256K1Group {
    type Field = Secp256K1ScalarField;

    type Element = ProjectivePoint;

    /// [SEC 1][1] serialization of a compressed point in secp256k1 takes 33 bytes
    /// (1-byte prefix and 32 bytes for the coordinate).
    ///
    /// Note that, in the SEC 1 spec, the identity is encoded as a single null byte;
    /// but here we pad with zeroes. This is acceptable as the identity _should_ never
    /// be serialized in FROST, else we error.
    ///
    /// [1]: https://secg.org/sec1-v2.pdf
    type Serialization = [u8; 33];

    fn cofactor() -> <Self::Field as Field>::Scalar {
        Scalar::ONE
    }

    fn identity() -> Self::Element {
        ProjectivePoint::IDENTITY
    }

    fn generator() -> Self::Element {
        ProjectivePoint::GENERATOR
    }

    fn serialize(element: &Self::Element) -> Result<Self::Serialization, GroupError> {
        if *element == Self::identity() {
            return Err(GroupError::InvalidIdentityElement);
        }
        let mut fixed_serialized = [0; 33];
        let serialized_point = element.to_affine().to_encoded_point(true);
        let serialized = serialized_point.as_bytes();
        fixed_serialized.copy_from_slice(serialized);
        Ok(fixed_serialized)
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, GroupError> {
        let encoded_point =
            k256::EncodedPoint::from_bytes(buf).map_err(|_| GroupError::MalformedElement)?;

        match Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded_point)) {
            Some(point) => {
                if point.is_identity().into() {
                    // This is actually impossible since the identity is encoded a a single byte
                    // which will never happen since we receive a 33-byte buffer.
                    // We leave the check for consistency.
                    Err(GroupError::InvalidIdentityElement)
                } else {
                    Ok(ProjectivePoint::from(point))
                }
            }
            None => Err(GroupError::MalformedElement),
        }
    }
}

fn hash_to_array(inputs: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for i in inputs {
        h.update(i);
    }
    let mut output = [0u8; 32];
    output.copy_from_slice(h.finalize().as_slice());
    output
}

fn hash_to_scalar(domain: &[&[u8]], msg: &[u8]) -> Scalar {
    let mut u = [Secp256K1ScalarField::zero()];
    hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&[msg], domain, &mut u)
        .expect("should never return error according to error cases described in ExpandMsgXmd");
    u[0]
}

/// Context string from the ciphersuite in the [spec].
///
/// [spec]: https://datatracker.ietf.org/doc/html/rfc9591#section-6.5-1
const CONTEXT_STRING: &str = "FROST-secp256k1-SHA256-v1";

/// An implementation of the FROST(secp256k1, SHA-256) ciphersuite.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Secp256K1Sha256;

impl Ciphersuite for Secp256K1Sha256 {
    const ID: &'static str = CONTEXT_STRING;

    type Group = Secp256K1Group;

    type HashOutput = [u8; 32];

    type SignatureSerialization = [u8; 65];

    /// H1 for FROST(secp256k1, SHA-256)
    ///
    /// [spec]: https://datatracker.ietf.org/doc/html/rfc9591#section-6.5-2.4.2.2
    fn H1(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"rho"], m)
    }

    /// H2 for FROST(secp256k1, SHA-256)
    ///
    /// [spec]: https://datatracker.ietf.org/doc/html/rfc9591#section-6.5-2.4.2.4
    fn H2(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"chal"], m)
    }

    /// H3 for FROST(secp256k1, SHA-256)
    ///
    /// [spec]: https://datatracker.ietf.org/doc/html/rfc9591#section-6.5-2.4.2.6
    fn H3(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"nonce"], m)
    }

    /// H4 for FROST(secp256k1, SHA-256)
    ///
    /// [spec]: https://datatracker.ietf.org/doc/html/rfc9591#section-6.5-2.4.2.8
    fn H4(m: &[u8]) -> Self::HashOutput {
        hash_to_array(&[CONTEXT_STRING.as_bytes(), b"msg", m])
    }

    /// H5 for FROST(secp256k1, SHA-256)
    ///
    /// [spec]: https://datatracker.ietf.org/doc/html/rfc9591#section-6.5-2.4.2.10
    fn H5(m: &[u8]) -> Self::HashOutput {
        hash_to_array(&[CONTEXT_STRING.as_bytes(), b"com", m])
    }

    /// HDKG for FROST(secp256k1, SHA-256)
    fn HDKG(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"dkg"], m))
    }

    /// HID for FROST(secp256k1, SHA-256)
    fn HID(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"id"], m))
    }
}

impl RandomizedCiphersuite for Secp256K1Sha256 {
    fn hash_randomizer(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(hash_to_scalar(
            &[CONTEXT_STRING.as_bytes(), b"randomizer"],
            m,
        ))
    }
}

type S = Secp256K1Sha256;

/// A FROST(secp256k1, SHA-256) participant identifier.
pub type Identifier = frost::Identifier<S>;

/// FROST(secp256k1, SHA-256) keys, key generation, key shares.
pub mod keys {
    use super::*;

    /// The identifier list to use when generating key shares.
    pub type IdentifierList<'a> = frost::keys::IdentifierList<'a, S>;

    /// Allows all participants' keys to be generated using a central, trusted
    /// dealer.
    pub fn generate_with_dealer<RNG: RngCore + CryptoRng>(
        max_signers: u16,
        min_signers: u16,
        identifiers: IdentifierList,
        mut rng: RNG,
    ) -> Result<(BTreeMap<Identifier, SecretShare>, PublicKeyPackage), Error> {
        frost::keys::generate_with_dealer(max_signers, min_signers, identifiers, &mut rng)
    }

    /// Splits an existing key into FROST shares.
    ///
    /// This is identical to [`generate_with_dealer`] but receives an existing key
    /// instead of generating a fresh one. This is useful in scenarios where
    /// the key needs to be generated externally or must be derived from e.g. a
    /// seed phrase.
    pub fn split<R: RngCore + CryptoRng>(
        secret: &SigningKey,
        max_signers: u16,
        min_signers: u16,
        identifiers: IdentifierList,
        rng: &mut R,
    ) -> Result<(BTreeMap<Identifier, SecretShare>, PublicKeyPackage), Error> {
        frost::keys::split(secret, max_signers, min_signers, identifiers, rng)
    }

    /// Recompute the secret from t-of-n secret shares using Lagrange interpolation.
    ///
    /// This can be used if for some reason the original key must be restored; e.g.
    /// if threshold signing is not required anymore.
    ///
    /// This is NOT required to sign with FROST; the whole point of FROST is being
    /// able to generate signatures only using the shares, without having to
    /// reconstruct the original key.
    ///
    /// The caller is responsible for providing at least `min_signers` shares;
    /// if less than that is provided, a different key will be returned.
    pub fn reconstruct(secret_shares: &[KeyPackage]) -> Result<SigningKey, Error> {
        frost::keys::reconstruct(secret_shares)
    }

    /// Secret and public key material generated by a dealer performing
    /// [`generate_with_dealer`].
    ///
    /// # Security
    ///
    /// To derive a FROST(secp256k1, SHA-256) keypair, the receiver of the [`SecretShare`] *must* call
    /// .into(), which under the hood also performs validation.
    pub type SecretShare = frost::keys::SecretShare<S>;

    /// A secret scalar value representing a signer's share of the group secret.
    pub type SigningShare = frost::keys::SigningShare<S>;

    /// A public group element that represents a single signer's public verification share.
    pub type VerifyingShare = frost::keys::VerifyingShare<S>;

    /// A FROST(secp256k1, SHA-256) keypair, which can be generated either by a trusted dealer or using
    /// a DKG.
    ///
    /// When using a central dealer, [`SecretShare`]s are distributed to
    /// participants, who then perform verification, before deriving
    /// [`KeyPackage`]s, which they store to later use during signing.
    pub type KeyPackage = frost::keys::KeyPackage<S>;

    /// Public data that contains all the signers' public keys as well as the
    /// group public key.
    ///
    /// Used for verification purposes before publishing a signature.
    pub type PublicKeyPackage = frost::keys::PublicKeyPackage<S>;

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
    pub type VerifiableSecretSharingCommitment = frost::keys::VerifiableSecretSharingCommitment<S>;

    pub mod dkg;
    pub mod refresh;
    pub mod repairable;
}

/// FROST(secp256k1, SHA-256) Round 1 functionality and types.
pub mod round1 {
    use crate::keys::SigningShare;

    use super::*;

    /// Comprised of FROST(secp256k1, SHA-256) hiding and binding nonces.
    ///
    /// Note that [`SigningNonces`] must be used *only once* for a signing
    /// operation; re-using nonces will result in leakage of a signer's long-lived
    /// signing key.
    pub type SigningNonces = frost::round1::SigningNonces<S>;

    /// Published by each participant in the first round of the signing protocol.
    ///
    /// This step can be batched if desired by the implementation. Each
    /// SigningCommitment can be used for exactly *one* signature.
    pub type SigningCommitments = frost::round1::SigningCommitments<S>;

    /// A commitment to a signing nonce share.
    pub type NonceCommitment = frost::round1::NonceCommitment<S>;

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Generates the signing nonces and commitments to be used in the signing
    /// operation.
    pub fn commit<RNG>(secret: &SigningShare, rng: &mut RNG) -> (SigningNonces, SigningCommitments)
    where
        RNG: CryptoRng + RngCore,
    {
        frost::round1::commit::<S, RNG>(secret, rng)
    }
}

/// Generated by the coordinator of the signing operation and distributed to
/// each signing party.
pub type SigningPackage = frost::SigningPackage<S>;

/// FROST(secp256k1, SHA-256) Round 2 functionality and types, for signature share generation.
pub mod round2 {
    use super::*;

    /// A FROST(secp256k1, SHA-256) participant's signature share, which the Coordinator will aggregate with all other signer's
    /// shares into the joint signature.
    pub type SignatureShare = frost::round2::SignatureShare<S>;

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Receives the message to be signed and a set of signing commitments and a set
    /// of randomizing commitments to be used in that signing operation, including
    /// that for this participant.
    ///
    /// Assumes the participant has already determined which nonce corresponds with
    /// the commitment that was assigned by the coordinator in the SigningPackage.
    pub fn sign(
        signing_package: &SigningPackage,
        signer_nonces: &round1::SigningNonces,
        key_package: &keys::KeyPackage,
    ) -> Result<SignatureShare, Error> {
        frost::round2::sign(signing_package, signer_nonces, key_package)
    }
}

/// A Schnorr signature on FROST(secp256k1, SHA-256).
pub type Signature = frost_core::Signature<S>;

/// Verifies each FROST(secp256k1, SHA-256) participant's signature share, and if all are valid,
/// aggregates the shares into a signature to publish.
///
/// Resulting signature is compatible with verification of a plain Schnorr
/// signature.
///
/// This operation is performed by a coordinator that can communicate with all
/// the signing participants before publishing the final signature. The
/// coordinator can be one of the participants or a semi-trusted third party
/// (who is trusted to not perform denial of service attacks, but does not learn
/// any secret information). Note that because the coordinator is trusted to
/// report misbehaving parties in order to avoid publishing an invalid
/// signature, if the coordinator themselves is a signer and misbehaves, they
/// can avoid that step. However, at worst, this results in a denial of
/// service attack due to publishing an invalid signature.
pub fn aggregate(
    signing_package: &SigningPackage,
    signature_shares: &BTreeMap<Identifier, round2::SignatureShare>,
    pubkeys: &keys::PublicKeyPackage,
) -> Result<Signature, Error> {
    frost::aggregate(signing_package, signature_shares, pubkeys)
}

/// A signing key for a Schnorr signature on FROST(secp256k1, SHA-256).
pub type SigningKey = frost_core::SigningKey<S>;

/// A valid verifying key for Schnorr signatures on FROST(secp256k1, SHA-256).
pub type VerifyingKey = frost_core::VerifyingKey<S>;
