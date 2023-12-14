//! Rerandomized FROST with Jubjub curve.
#![allow(non_snake_case)]
#![deny(missing_docs)]

mod constants;
mod hash;

use std::collections::BTreeMap;

use group::GroupEncoding;
use group::{ff::Field as FFField, ff::PrimeField};

// Re-exports in our public API
#[cfg(feature = "serde")]
pub use frost_rerandomized::frost_core::serde;
pub use frost_rerandomized::frost_core::{
    self as frost, Ciphersuite, Field, FieldError, Group, GroupError,
};
use frost_rerandomized::RandomizedCiphersuite;

use rand_core::{CryptoRng, RngCore};

use crate::hash::HStar;

const CONTEXT_STRING: &str = "FROST-RedJubjub-BLAKE2b-512-v1";

fn hash_to_array(inputs: &[&[u8]]) -> [u8; 64] {
    let mut state = HStar::default();
    for i in &inputs[1..] {
        state.update(i);
    }
    *state.state.finalize().as_array()
}
fn hash_to_scalar(domain: &[u8], msg: &[u8]) -> jubjub::Scalar {
    HStar::default().update(domain).update(msg).finalize()
}

/// An error type for the FROST(Jubjub, BLAKE2b-512) ciphersuite.
pub type Error = frost_rerandomized::frost_core::Error<JubjubBlake2b512>;

/// An implementation of the FROST(Jubjub, BLAKE2b-512) ciphersuite scalar field.
#[derive(Clone, Copy)]
pub struct JubjubScalarField;

impl Field for JubjubScalarField {
    type Scalar = jubjub::Scalar;

    type Serialization = [u8; 32];

    fn zero() -> Self::Scalar {
        Self::Scalar::zero()
    }

    fn one() -> Self::Scalar {
        Self::Scalar::one()
    }

    fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, FieldError> {
        // [`Jubjub::Scalar`]'s Eq/PartialEq does a constant-time comparison using
        // `ConstantTimeEq`
        if *scalar == <Self as Field>::zero() {
            Err(FieldError::InvalidZeroScalar)
        } else {
            Ok(Self::Scalar::invert(scalar).unwrap())
        }
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Self::Scalar::random(rng)
    }

    fn serialize(scalar: &Self::Scalar) -> Self::Serialization {
        scalar.to_bytes()
    }

    fn little_endian_serialize(scalar: &Self::Scalar) -> Self::Serialization {
        Self::serialize(scalar)
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, FieldError> {
        match Self::Scalar::from_repr(*buf).into() {
            Some(s) => Ok(s),
            None => Err(FieldError::MalformedScalar),
        }
    }
}

/// An implementation of the FROST(Jubjub, BLAKE2b-512) ciphersuite group.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct JubjubGroup;

impl Group for JubjubGroup {
    type Field = JubjubScalarField;

    type Element = jubjub::ExtendedPoint;

    type Serialization = [u8; 32];

    fn cofactor() -> <Self::Field as Field>::Scalar {
        Self::Field::one()
    }

    fn identity() -> Self::Element {
        Self::Element::identity()
    }

    fn generator() -> Self::Element {
        jubjub::AffinePoint::from_bytes(constants::SPENDAUTHSIG_BASEPOINT_BYTES)
            .unwrap()
            .into()
    }

    fn serialize(element: &Self::Element) -> Self::Serialization {
        element.to_bytes()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, GroupError> {
        let point = Self::Element::from_bytes(buf);

        match Option::<Self::Element>::from(point) {
            Some(point) => {
                if point == Self::identity() {
                    Err(GroupError::InvalidIdentityElement)
                } else if point.is_torsion_free().into() {
                    Ok(point)
                } else {
                    Err(GroupError::InvalidNonPrimeOrderElement)
                }
            }
            None => Err(GroupError::MalformedElement),
        }
    }
}

/// An implementation of the FROST(Jubjub, BLAKE2b-512) ciphersuite.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct JubjubBlake2b512;

impl Ciphersuite for JubjubBlake2b512 {
    const ID: &'static str = CONTEXT_STRING;

    type Group = JubjubGroup;

    type HashOutput = [u8; 64];

    type SignatureSerialization = [u8; 64];

    /// H1 for FROST(Jubjub, BLAKE2b-512)
    fn H1(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        hash_to_scalar((CONTEXT_STRING.to_owned() + "rho").as_bytes(), m)
    }

    /// H2 for FROST(Jubjub, BLAKE2b-512)
    fn H2(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        hash_to_scalar((CONTEXT_STRING.to_owned() + "chal").as_bytes(), m)
    }

    /// H3 for FROST(Jubjub, BLAKE2b-512)
    fn H3(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        hash_to_scalar((CONTEXT_STRING.to_owned() + "nonce").as_bytes(), m)
    }

    /// H4 for FROST(Jubjub, BLAKE2b-512)
    fn H4(m: &[u8]) -> Self::HashOutput {
        hash_to_array(&[CONTEXT_STRING.as_bytes(), b"msg", m])
    }

    /// H5 for FROST(Jubjub, BLAKE2b-512)
    fn H5(m: &[u8]) -> Self::HashOutput {
        hash_to_array(&[CONTEXT_STRING.as_bytes(), b"com", m])
    }

    /// HDKG for FROST(Jubjub, BLAKE2b-512)
    fn HDKG(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(hash_to_scalar(
            (CONTEXT_STRING.to_owned() + "dkg").as_bytes(),
            m,
        ))
    }

    /// HID for FROST(Jubjub, BLAKE2b-512)
    fn HID(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(hash_to_scalar(
            (CONTEXT_STRING.to_owned() + "id").as_bytes(),
            m,
        ))
    }
}

impl RandomizedCiphersuite for JubjubBlake2b512 {
    fn hash_randomizer(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(hash_to_scalar(
            (CONTEXT_STRING.to_owned() + "randomizer").as_bytes(),
            m,
        ))
    }
}

// Shorthand alias for the ciphersuite
type J = JubjubBlake2b512;

/// A FROST(Jubjub, BLAKE2b-512) participant identifier.
pub type Identifier = frost::Identifier<J>;

/// FROST(Jubjub, BLAKE2b-512) keys, key generation, key shares.
pub mod keys {
    use std::collections::BTreeMap;

    use super::*;

    /// The identifier list to use when generating key shares.
    pub type IdentifierList<'a> = frost::keys::IdentifierList<'a, J>;

    /// Allows all participants' keys to be generated using a central, trusted
    /// dealer.
    pub fn generate_with_dealer<R: RngCore + CryptoRng>(
        max_signers: u16,
        min_signers: u16,
        identifiers: IdentifierList,
        mut rng: R,
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
        key: &SigningKey,
        max_signers: u16,
        min_signers: u16,
        identifiers: IdentifierList,
        rng: &mut R,
    ) -> Result<(BTreeMap<Identifier, SecretShare>, PublicKeyPackage), Error> {
        frost::keys::split(key, max_signers, min_signers, identifiers, rng)
    }

    /// Secret and public key material generated by a dealer performing
    /// [`generate_with_dealer`].
    ///
    /// # Security
    ///
    /// To derive a FROST(Jubjub, BLAKE2b-512) keypair, the receiver of the [`SecretShare`] *must* call
    /// .into(), which under the hood also performs validation.
    pub type SecretShare = frost::keys::SecretShare<J>;

    /// A secret scalar value representing a signer's share of the group secret.
    pub type SigningShare = frost::keys::SigningShare<J>;

    /// A public group element that represents a single signer's public verification share.
    pub type VerifyingShare = frost::keys::VerifyingShare<J>;

    /// A FROST(Jubjub, BLAKE2b-512) keypair, which can be generated either by a trusted dealer or using
    /// a DKG.
    ///
    /// When using a central dealer, [`SecretShare`]s are distributed to
    /// participants, who then perform verification, before deriving
    /// [`KeyPackage`]s, which they store to later use during signing.
    pub type KeyPackage = frost::keys::KeyPackage<J>;

    /// Public data that contains all the signers' public keys as well as the
    /// group public key.
    ///
    /// Used for verification purposes before publishing a signature.
    pub type PublicKeyPackage = frost::keys::PublicKeyPackage<J>;

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
    pub type VerifiableSecretSharingCommitment = frost::keys::VerifiableSecretSharingCommitment<J>;

    pub mod dkg;
    pub mod repairable;
}

/// FROST(Jubjub, BLAKE2b-512) Round 1 functionality and types.
pub mod round1 {
    use frost_rerandomized::frost_core::keys::SigningShare;

    use super::*;
    /// Comprised of FROST(Jubjub, BLAKE2b-512) hiding and binding nonces.
    ///
    /// Note that [`SigningNonces`] must be used *only once* for a signing
    /// operation; re-using nonces will result in leakage of a signer's long-lived
    /// signing key.
    pub type SigningNonces = frost::round1::SigningNonces<J>;

    /// Published by each participant in the first round of the signing protocol.
    ///
    /// This step can be batched if desired by the implementation. Each
    /// SigningCommitment can be used for exactly *one* signature.
    pub type SigningCommitments = frost::round1::SigningCommitments<J>;

    /// A commitment to a signing nonce share.
    pub type NonceCommitment = frost::round1::NonceCommitment<J>;

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Generates the signing nonces and commitments to be used in the signing
    /// operation.
    pub fn commit<R>(secret: &SigningShare<J>, rng: &mut R) -> (SigningNonces, SigningCommitments)
    where
        R: CryptoRng + RngCore,
    {
        frost::round1::commit::<J, R>(secret, rng)
    }
}

/// Generated by the coordinator of the signing operation and distributed to
/// each signing party.
pub type SigningPackage = frost::SigningPackage<J>;

/// FROST(Jubjub, BLAKE2b-512) Round 2 functionality and types, for signature share generation.
pub mod round2 {
    use super::*;

    /// A FROST(Jubjub, BLAKE2b-512) participant's signature share, which the Coordinator will aggregate with all other signer's
    /// shares into the joint signature.
    pub type SignatureShare = frost::round2::SignatureShare<J>;

    /// A randomizer. A random scalar which is used to randomize the key.
    pub type Randomizer = frost_rerandomized::Randomizer<J>;

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
        randomizer: Randomizer,
    ) -> Result<SignatureShare, Error> {
        frost_rerandomized::sign(signing_package, signer_nonces, key_package, randomizer)
    }
}

/// A Schnorr signature on FROST(Jubjub, BLAKE2b-512).
pub type Signature = frost_rerandomized::frost_core::Signature<J>;

/// Randomized parameters for a signing instance of randomized FROST.
pub type RandomizedParams = frost_rerandomized::RandomizedParams<J>;

/// Verifies each FROST(Jubjub, BLAKE2b-512) participant's signature share, and if all are valid,
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
    randomized_params: &RandomizedParams,
) -> Result<Signature, Error> {
    frost_rerandomized::aggregate(
        signing_package,
        signature_shares,
        pubkeys,
        randomized_params,
    )
}

/// A signing key for a Schnorr signature on FROST(Jubjub, BLAKE2b-512).
pub type SigningKey = frost_rerandomized::frost_core::SigningKey<J>;

/// A valid verifying key for Schnorr signatures on FROST(Jubjub, BLAKE2b-512).
pub type VerifyingKey = frost_rerandomized::frost_core::VerifyingKey<J>;
