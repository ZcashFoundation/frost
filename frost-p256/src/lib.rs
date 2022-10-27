#![allow(non_snake_case)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use p256::{
    elliptic_curve::{
        group::prime::PrimeCurveAffine,
        hash2curve::{hash_to_field, ExpandMsgXmd},
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field as FFField, PrimeField,
    },
    AffinePoint, ProjectivePoint, Scalar,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{digest::Update, Digest, Sha256};

use frost_core::{frost, Ciphersuite, Field, Group};

#[cfg(test)]
mod tests;

pub use frost_core::Error;

#[derive(Clone, Copy)]
/// An implementation of the FROST(P-256, SHA-256) ciphersuite scalar field.
pub struct P256ScalarField;

impl Field for P256ScalarField {
    type Scalar = Scalar;

    type Serialization = [u8; 32];

    fn zero() -> Self::Scalar {
        Scalar::ZERO
    }

    fn one() -> Self::Scalar {
        Scalar::ONE
    }

    fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, Error> {
        // [`p256::Scalar`]'s Eq/PartialEq does a constant-time comparison using
        // `ConstantTimeEq`
        if *scalar == <Self as Field>::zero() {
            Err(Error::InvalidZeroScalar)
        } else {
            Ok(scalar.invert().unwrap())
        }
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Scalar::random(rng)
    }

    fn random_nonzero<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        loop {
            let scalar = Scalar::random(&mut *rng);

            // This impl of `Eq` calls to `ConstantTimeEq` under the hood
            if scalar != Scalar::zero() {
                return scalar;
            }
        }
    }

    fn serialize(scalar: &Self::Scalar) -> Self::Serialization {
        scalar.to_bytes().into()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, Error> {
        let field_bytes: &p256::FieldBytes = buf.into();
        match Scalar::from_repr(*field_bytes).into() {
            Some(s) => Ok(s),
            None => Err(Error::MalformedScalar),
        }
    }

    fn little_endian_serialize(scalar: &Self::Scalar) -> Self::Serialization {
        let mut array = Self::serialize(scalar);
        array.reverse();
        array
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// An implementation of the FROST(P-256, SHA-256) ciphersuite group.
pub struct P256Group;

impl Group for P256Group {
    type Field = P256ScalarField;

    type Element = ProjectivePoint;

    /// [SEC 1][1] serialization of a compressed point in P-256 takes 33 bytes
    /// (1-byte prefix and 32 bytes for the coordinate).
    ///
    /// Note that, in the P-256 spec, the identity is encoded as a single null byte;
    /// but here we pad with zeroes. This is acceptable as the identity _should_ never
    /// be serialized in FROST, else we error.
    ///
    /// [1]: https://secg.org/sec1-v2.pdf
    type Serialization = [u8; 33];

    fn cofactor() -> <Self::Field as Field>::Scalar {
        Scalar::one()
    }

    fn identity() -> Self::Element {
        ProjectivePoint::IDENTITY
    }

    fn generator() -> Self::Element {
        ProjectivePoint::GENERATOR
    }

    fn serialize(element: &Self::Element) -> Self::Serialization {
        let mut fixed_serialized = [0; 33];
        let serialized_point = element.to_affine().to_encoded_point(true);
        let serialized = serialized_point.as_bytes();
        // Sanity check; either it takes all bytes or a single byte (identity).
        assert!(serialized.len() == fixed_serialized.len() || serialized.len() == 1);
        // Copy to the left of the buffer (i.e. pad the identity with zeroes).
        // TODO: Note that identity elements shouldn't be serialized in FROST. This will likely become
        // part of the API and when that happens, we should return an error instead of
        // doing this padding.
        {
            let (left, _right) = fixed_serialized.split_at_mut(serialized.len());
            left.copy_from_slice(serialized);
        }
        fixed_serialized
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, Error> {
        let encoded_point =
            p256::EncodedPoint::from_bytes(buf).map_err(|_| Error::MalformedElement)?;

        match Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded_point)) {
            Some(point) => {
                if point.is_identity().into() {
                    // This is actually impossible since the identity is encoded a a single byte
                    // which will never happen since we receive a 33-byte buffer.
                    // We leave the check for consistency.
                    Err(Error::InvalidIdentityElement)
                } else {
                    Ok(ProjectivePoint::from(point))
                }
            }
            None => Err(Error::MalformedElement),
        }
    }
}

/// Context string from the ciphersuite in the [spec]
///
/// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-6.4-1
const CONTEXT_STRING: &str = "FROST-P256-SHA256-v11";

#[derive(Clone, Copy, PartialEq, Eq)]
/// An implementation of the FROST(P-256, SHA-256) ciphersuite.
pub struct P256Sha256;

impl Ciphersuite for P256Sha256 {
    type Group = P256Group;

    type HashOutput = [u8; 32];

    type SignatureSerialization = [u8; 65];

    /// H1 for FROST(P-256, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-6.4-2.2.2.1
    fn H1(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let mut u = [P256ScalarField::zero()];
        let dst = CONTEXT_STRING.to_owned() + "rho";
        hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&[m], dst.as_bytes(), &mut u)
            .expect("should never return error according to error cases described in ExpandMsgXmd");
        u[0]
    }

    /// H2 for FROST(P-256, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-6.4-2.2.2.2
    fn H2(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let mut u = [P256ScalarField::zero()];
        let dst = CONTEXT_STRING.to_owned() + "chal";
        hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&[m], dst.as_bytes(), &mut u)
            .expect("should never return error according to error cases described in ExpandMsgXmd");
        u[0]
    }

    /// H3 for FROST(P-256, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-6.4-2.2.2.3
    fn H3(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let mut u = [P256ScalarField::zero()];
        let dst = CONTEXT_STRING.to_owned() + "nonce";
        hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&[m], dst.as_bytes(), &mut u)
            .expect("should never return error according to error cases described in ExpandMsgXmd");
        u[0]
    }

    /// H4 for FROST(P-256, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-6.4-2.2.2.4
    fn H4(m: &[u8]) -> Self::HashOutput {
        let h = Sha256::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("msg")
            .chain(m);

        let mut output = [0u8; 32];
        output.copy_from_slice(h.finalize().as_slice());
        output
    }

    /// H5 for FROST(P-256, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-6.4-2.2.2.5
    fn H5(m: &[u8]) -> Self::HashOutput {
        let h = Sha256::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("com")
            .chain(m);

        let mut output = [0u8; 32];
        output.copy_from_slice(h.finalize().as_slice());
        output
    }

    /// HDKG for FROST(P-256, SHA-256)
    fn HDKG(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        let mut u = [P256ScalarField::zero()];
        let dst = CONTEXT_STRING.to_owned() + "dkg";
        hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&[m], dst.as_bytes(), &mut u)
            .expect("should never return error according to error cases described in ExpandMsgXmd");
        Some(u[0])
    }
}

// Shorthand alias for the ciphersuite
type P = P256Sha256;

/// A FROST(P-256, SHA-256) participant identifier.
pub type Identifier = frost::Identifier<P>;

/// FROST(P-256, SHA-256) keys, key generation, key shares.
pub mod keys {
    use super::*;

    /// Allows all participants' keys to be generated using a central, trusted
    /// dealer.
    pub fn keygen_with_dealer<RNG: RngCore + CryptoRng>(
        max_signers: u16,
        min_signers: u16,
        mut rng: RNG,
    ) -> Result<(Vec<SecretShare>, PublicKeyPackage), Error> {
        frost::keys::keygen_with_dealer(max_signers, min_signers, &mut rng)
    }

    /// Secret and public key material generated by a dealer performing
    /// [`keygen_with_dealer`].
    ///
    /// # Security
    ///
    /// To derive a FROST(P-256, SHA-256) keypair, the receiver of the [`SecretShare`] *must* call
    /// .into(), which under the hood also performs validation.
    pub type SecretShare = frost::keys::SecretShare<P>;

    /// A FROST(P-256, SHA-256) keypair, which can be generated either by a trusted dealer or using
    /// a DKG.
    ///
    /// When using a central dealer, [`SecretShare`]s are distributed to
    /// participants, who then perform verification, before deriving
    /// [`KeyPackage`]s, which they store to later use during signing.
    pub type KeyPackage = frost::keys::KeyPackage<P>;

    /// Public data that contains all the signers' public keys as well as the
    /// group public key.
    ///
    /// Used for verification purposes before publishing a signature.
    pub type PublicKeyPackage = frost::keys::PublicKeyPackage<P>;
}

/// FROST(P-256, SHA-256) Round 1 functionality and types.
pub mod round1 {
    use frost_core::frost::keys::SigningShare;

    use super::*;
    /// Comprised of FROST(P-256, SHA-256) hiding and binding nonces.
    ///
    /// Note that [`SigningNonces`] must be used *only once* for a signing
    /// operation; re-using nonces will result in leakage of a signer's long-lived
    /// signing key.
    pub type SigningNonces = frost::round1::SigningNonces<P>;

    /// Published by each participant in the first round of the signing protocol.
    ///
    /// This step can be batched if desired by the implementation. Each
    /// SigningCommitment can be used for exactly *one* signature.
    pub type SigningCommitments = frost::round1::SigningCommitments<P>;

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Generates the signing nonces and commitments to be used in the signing
    /// operation.
    pub fn commit<RNG>(
        participant_identifier: frost::Identifier<P>,
        secret: &SigningShare<P>,
        rng: &mut RNG,
    ) -> (SigningNonces, SigningCommitments)
    where
        RNG: CryptoRng + RngCore,
    {
        frost::round1::commit::<P, RNG>(participant_identifier, secret, rng)
    }
}

/// Generated by the coordinator of the signing operation and distributed to
/// each signing party.
pub type SigningPackage = frost::SigningPackage<P>;

/// FROST(P-256, SHA-256) Round 2 functionality and types, for signature share generation.
pub mod round2 {
    use super::*;

    /// A FROST(P-256, SHA-256) participant's signature share, which the Coordinator will aggregate with all other signer's
    /// shares into the joint signature.
    pub type SignatureShare = frost::round2::SignatureShare<P>;

    /// Generated by the coordinator of the signing operation and distributed to
    /// each signing party
    pub type SigningPackage = frost::SigningPackage<P>;

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

/// A Schnorr signature on FROST(P-256, SHA-256).
pub type Signature = frost_core::Signature<P>;

/// Verifies each FROST(P-256, SHA-256) participant's signature share, and if all are valid,
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
    signing_package: &round2::SigningPackage,
    signature_shares: &[round2::SignatureShare],
    pubkeys: &keys::PublicKeyPackage,
) -> Result<Signature, Error> {
    frost::aggregate(signing_package, signature_shares, pubkeys)
}

/// A signing key for a Schnorr signature on FROST(P-256, SHA-256).
pub type SigningKey = frost_core::SigningKey<P>;

/// A valid verifying key for Schnorr signatures on FROST(P-256, SHA-256).
pub type VerifyingKey = frost_core::VerifyingKey<P>;
