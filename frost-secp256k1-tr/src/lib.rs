#![allow(non_snake_case)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc = document_features::document_features!()]

use std::collections::BTreeMap;

use frost_rerandomized::RandomizedCiphersuite;
use k256::{
    elliptic_curve::{
        bigint::U256,
        group::prime::PrimeCurveAffine,
        hash2curve::{hash_to_field, ExpandMsgXmd},
        point::AffineCoordinates,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field as FFField, PrimeField, ScalarPrimitive,
    },
    AffinePoint, ProjectivePoint, Scalar,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use frost_core as frost;

#[cfg(test)]
mod tests;

// Re-exports in our public API
pub use frost_core::{
    serde, Challenge, Ciphersuite, Element, Field, FieldError, Group, GroupCommitment, GroupError,
};

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

    fn negate(scalar: &Self::Scalar) -> Self::Scalar {
        -scalar
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

    fn y_is_odd(element: &Self::Element) -> bool {
        element.to_affine().y_is_odd().into()
    }

    fn serialize(element: &Self::Element) -> Self::Serialization {
        let mut fixed_serialized = [0; 33];
        let serialized_point = element.to_affine().to_encoded_point(true);
        let serialized = serialized_point.as_bytes();
        // Sanity check; either it takes all bytes or a single byte (identity).
        assert!(serialized.len() == fixed_serialized.len() || serialized.len() == 1);
        // Copy to the left of the buffer (i.e. pad the identity with zeroes).
        // Note that identity elements shouldn't be serialized in FROST, but we
        // do this padding so that this function doesn't have to return an error.
        // If this encodes the identity, it will fail when deserializing.
        {
            let (left, _right) = fixed_serialized.split_at_mut(serialized.len());
            left.copy_from_slice(serialized);
        }
        fixed_serialized
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

fn hash_to_scalar(domain: &[u8], msg: &[u8]) -> Scalar {
    let mut u = [Secp256K1ScalarField::zero()];
    hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&[msg], &[domain], &mut u)
        .expect("should never return error according to error cases described in ExpandMsgXmd");
    u[0]
}

/// Context string from the ciphersuite in the [spec].
///
/// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-6.5-1
const CONTEXT_STRING: &str = "FROST-secp256k1-SHA256-TR-v1";

/// An implementation of the FROST(secp256k1, SHA-256) ciphersuite.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Secp256K1Sha256;

/// Digest the hasher to a Scalar
fn hasher_to_scalar(hasher: Sha256) -> Scalar {
    let sp = ScalarPrimitive::new(U256::from_be_slice(&hasher.finalize())).unwrap();
    Scalar::from(&sp)
}

/// Create a BIP340 compliant tagged hash
fn tagged_hash(tag: &str) -> Sha256 {
    let mut hasher = Sha256::new();
    let mut tag_hasher = Sha256::new();
    tag_hasher.update(tag.as_bytes());
    let tag_hash = tag_hasher.finalize();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher
}

/// Create a BIP341 compliant taproot tweak
fn tweak<T: AsRef<[u8]>>(
    public_key: &<<Secp256K1Sha256 as Ciphersuite>::Group as Group>::Element,
    merkle_root: Option<T>,
) -> Scalar {
    match merkle_root {
        None => Secp256K1ScalarField::zero(),
        Some(root) => {
            let mut hasher = tagged_hash("TapTweak");
            hasher.update(public_key.to_affine().x());
            hasher.update(root.as_ref());
            hasher_to_scalar(hasher)
        }
    }
}

/// Create a BIP341 compliant tweaked public key
fn tweaked_public_key<T: AsRef<[u8]>>(
    public_key: &VerifyingKey,
    merkle_root: Option<T>,
) -> <<Secp256K1Sha256 as Ciphersuite>::Group as Group>::Element {
    let mut pk = public_key.to_element();
    if pk.to_affine().y_is_odd().into() {
        pk = -pk;
    }
    ProjectivePoint::GENERATOR * tweak(&pk, merkle_root) + pk
}

/// The message target which the group's signature should commit to. Includes
/// a message byte vector, and a set of ciphersuite-specific parameters.
pub type SigningTarget = frost_core::SigningTarget<S>;

/// The ciphersuite-specific signing parameters which are fed into
/// signing code to ensure correctly compliant signatures are computed.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SigningParameters {
    /// The tapscript merkle tree root which must be committed to and agreed upon
    /// in advance by all participants in the signing round.
    ///
    /// If set to `None` (the default), then no taproot tweak will be committed to in the signature.
    /// Best practice suggested by BIP341 is to commit to an empty merkle root in cases
    /// where no tapscript tweak is needed, i.e. by supplying `&[0; u8]` as the merkle root.
    /// This prevents hiding of taproot commitments inside a linearly aggregated key.
    ///
    /// However, for FROST, this is not strictly required as the group key cannot be
    /// poisoned as long as the DKG procedure is conducted correctly.
    /// Thus, the [`Default`] trait implementation of taproot `SigningParameters`
    /// sets `tapscript_merkle_root` to `None`.
    ///
    /// If 3rd party observers outside the FROST group must be able to verify there
    /// is no hidden script-spending path embedded in the FROST group's taproot output key,
    /// then you should set `tapscript_merkle_root` to `Some(vec![])`, which proves
    /// the tapscript commitment for the tweaked output key is unspendable.
    pub tapscript_merkle_root: Option<Vec<u8>>,
}

impl frost_core::SigningParameters for SigningParameters {}

impl Ciphersuite for Secp256K1Sha256 {
    const ID: &'static str = CONTEXT_STRING;

    type Group = Secp256K1Group;

    type HashOutput = [u8; 32];

    type SignatureSerialization = [u8; 64];

    type SigningParameters = SigningParameters;

    /// H1 for FROST(secp256k1, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-6.5-2.2.2.1
    fn H1(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        hash_to_scalar((CONTEXT_STRING.to_owned() + "rho").as_bytes(), m)
    }

    /// H2 for FROST(secp256k1, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-6.5-2.2.2.2
    fn H2(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let mut hasher = tagged_hash("BIP0340/challenge");
        hasher.update(m);
        hasher_to_scalar(hasher)
    }

    /// H3 for FROST(secp256k1, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-6.5-2.2.2.3
    fn H3(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        hash_to_scalar((CONTEXT_STRING.to_owned() + "nonce").as_bytes(), m)
    }

    /// H4 for FROST(secp256k1, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-6.5-2.2.2.4
    fn H4(m: &[u8]) -> Self::HashOutput {
        hash_to_array(&[CONTEXT_STRING.as_bytes(), b"msg", m])
    }

    /// H5 for FROST(secp256k1, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-6.5-2.2.2.5
    fn H5(m: &[u8]) -> Self::HashOutput {
        hash_to_array(&[CONTEXT_STRING.as_bytes(), b"com", m])
    }

    /// HDKG for FROST(secp256k1, SHA-256)
    fn HDKG(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(hash_to_scalar(
            (CONTEXT_STRING.to_owned() + "dkg").as_bytes(),
            m,
        ))
    }

    /// HID for FROST(secp256k1, SHA-256)
    fn HID(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(hash_to_scalar(
            (CONTEXT_STRING.to_owned() + "id").as_bytes(),
            m,
        ))
    }

    /// Generates the challenge as is required for Schnorr signatures.
    fn challenge(
        R: &Element<S>,
        verifying_key: &VerifyingKey,
        sig_target: &SigningTarget,
    ) -> Challenge<S> {
        let mut preimage = vec![];
        let tweaked_pk = tweaked_public_key(
            &verifying_key,
            sig_target.sig_params().tapscript_merkle_root.as_ref(),
        );
        preimage.extend_from_slice(&R.to_affine().x());
        preimage.extend_from_slice(&tweaked_pk.to_affine().x());
        preimage.extend_from_slice(sig_target.message().as_ref());
        Challenge::from_scalar(S::H2(&preimage[..]))
    }

    /// Finalizes the signature by negating it depending on whether
    /// the group [`VerifyingKey`] is even or odd parity.
    fn aggregate_sig_finalize(
        z_raw: <<Self::Group as Group>::Field as Field>::Scalar,
        R: Element<Self>,
        verifying_key: &VerifyingKey,
        sig_target: &SigningTarget,
    ) -> Signature {
        let challenge = Self::challenge(&R, verifying_key, &sig_target);

        let t = tweak(
            verifying_key.element(),
            sig_target.sig_params().tapscript_merkle_root.as_ref(),
        );
        let tc = t * challenge.clone().to_scalar();
        let tweaked_pubkey = tweaked_public_key(
            verifying_key,
            sig_target.sig_params().tapscript_merkle_root.as_ref(),
        );
        let z_tweaked = if tweaked_pubkey.to_affine().y_is_odd().into() {
            z_raw - tc
        } else {
            z_raw + tc
        };
        Signature::new(R, z_tweaked)
    }

    /// Finalize a single-signer BIP340 Schnorr signature.
    fn single_sig_finalize(
        k: <<Self::Group as Group>::Field as Field>::Scalar,
        R: Element<Self>,
        secret: <<Self::Group as Group>::Field as Field>::Scalar,
        challenge: &Challenge<S>,
        verifying_key: &VerifyingKey,
        sig_params: &SigningParameters,
    ) -> Signature {
        let tweaked_pubkey =
            tweaked_public_key(verifying_key, sig_params.tapscript_merkle_root.as_ref());
        let c = challenge.clone().to_scalar();
        let z = if tweaked_pubkey.to_affine().y_is_odd().into() {
            k - (c * secret)
        } else {
            k + (c * secret)
        };
        Signature::new(R, z)
    }

    /// Serialize a signature in compact BIP340 format, with an x-only R point.
    fn serialize_signature(signature: &Signature) -> Self::SignatureSerialization {
        let R_bytes = Self::Group::serialize(signature.R());
        let z_bytes = <Self::Group as Group>::Field::serialize(signature.z());

        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&R_bytes[1..]);
        bytes[32..].copy_from_slice(&z_bytes);
        bytes
    }

    /// Deserialize a signature in compact BIP340 format, with an x-only R point.
    fn deserialize_signature(bytes: Self::SignatureSerialization) -> Result<Signature, Error> {
        if bytes.len() != 64 {
            return Err(Error::MalformedSignature);
        }

        let mut R_bytes = [0u8; 33];
        R_bytes[0] = 0x02; // taproot signatures always have an even R point
        R_bytes[1..].copy_from_slice(&bytes[..32]);

        let mut z_bytes = [0u8; 32];
        z_bytes.copy_from_slice(&bytes[32..]);

        let R = Self::Group::deserialize(&R_bytes)?;
        let z = <Self::Group as Group>::Field::deserialize(&z_bytes)?;

        Ok(Signature::new(R, z))
    }

    /// Compute a signature share, negating if required by BIP340.
    fn compute_signature_share(
        signer_nonces: &round1::SigningNonces,
        binding_factor: frost::BindingFactor<S>,
        group_commitment: GroupCommitment<S>,
        lambda_i: <<Self::Group as Group>::Field as Field>::Scalar,
        key_package: &frost::keys::KeyPackage<S>,
        challenge: Challenge<S>,
        sig_params: &SigningParameters,
    ) -> round2::SignatureShare {
        let mut sn = signer_nonces.clone();
        if group_commitment.y_is_odd() {
            sn.negate_nonces();
        }

        let mut kp = key_package.clone();
        let public_key = key_package.verifying_key();
        let pubkey_is_odd: bool = public_key.y_is_odd();
        let tweaked_pubkey_is_odd: bool =
            tweaked_public_key(public_key, sig_params.tapscript_merkle_root.as_ref())
                .to_affine()
                .y_is_odd()
                .into();
        if pubkey_is_odd != tweaked_pubkey_is_odd {
            kp.negate_signing_share();
        }

        frost::round2::compute_signature_share(&sn, binding_factor, lambda_i, &kp, challenge)
    }

    /// Computes the effective pubkey point by tweaking the verifying key with a
    /// provably unspendable taproot tweak.
    fn effective_pubkey_element(
        public_key: &VerifyingKey,
        sig_params: &SigningParameters,
    ) -> <Self::Group as Group>::Element {
        let tweaked_pubkey =
            tweaked_public_key(public_key, sig_params.tapscript_merkle_root.as_ref());
        if Self::Group::y_is_odd(&tweaked_pubkey) {
            -tweaked_pubkey
        } else {
            tweaked_pubkey
        }
    }

    /// Ensures the nonce has an even Y coordinate.
    fn effective_nonce_element(
        R: <Self::Group as Group>::Element,
    ) -> <Self::Group as Group>::Element {
        if Self::Group::y_is_odd(&R) {
            -R
        } else {
            R
        }
    }

    /// Ensures the secret key is negated if the public key has odd parity.
    fn effective_secret_key(
        secret: <<Self::Group as Group>::Field as Field>::Scalar,
        public_key: &VerifyingKey,
        sig_params: &SigningParameters,
    ) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let t = tweak(
            public_key.element(),
            sig_params.tapscript_merkle_root.as_ref(),
        );
        if Self::Group::y_is_odd(public_key.element()) {
            -secret + t
        } else {
            secret + t
        }
    }

    /// Ensures the nonce secret is negated if the public nonce point has odd parity.
    fn effective_nonce_secret(
        nonce: <<Self::Group as Group>::Field as Field>::Scalar,
        R: &Element<Self>,
    ) -> <<Self::Group as Group>::Field as Field>::Scalar {
        if R.to_affine().y_is_odd().into() {
            -nonce
        } else {
            nonce
        }
    }

    /// Ensures the commitment share is negated if the group's commitment has odd parity.
    fn effective_commitment_share(
        group_commitment_share: frost::round1::GroupCommitmentShare<Self>,
        group_commitment: &GroupCommitment<Self>,
    ) -> Element<Self> {
        if group_commitment
            .clone()
            .to_element()
            .to_affine()
            .y_is_odd()
            .into()
        {
            -group_commitment_share.to_element()
        } else {
            group_commitment_share.to_element()
        }
    }

    /// Calculate a verifying share compatible with taproot, depending on the parity
    /// of the tweaked vs untweaked verifying key.
    fn effective_verifying_share(
        verifying_share: &keys::VerifyingShare,
        verifying_key: &VerifyingKey,
        sig_params: &SigningParameters,
    ) -> <Self::Group as Group>::Element {
        let pubkey_is_odd: bool = verifying_key.to_element().to_affine().y_is_odd().into();
        let tweaked_pubkey_is_odd: bool =
            tweaked_public_key(verifying_key, sig_params.tapscript_merkle_root.as_ref())
                .to_affine()
                .y_is_odd()
                .into();

        let vs = verifying_share.to_element();
        if pubkey_is_odd != tweaked_pubkey_is_odd {
            -vs
        } else {
            vs
        }
    }
}

impl RandomizedCiphersuite for Secp256K1Sha256 {
    fn hash_randomizer(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(hash_to_scalar(
            (CONTEXT_STRING.to_owned() + "randomizer").as_bytes(),
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
    use std::collections::BTreeMap;

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
