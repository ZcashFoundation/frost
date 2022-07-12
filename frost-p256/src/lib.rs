#![allow(non_snake_case)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use p256::{
    elliptic_curve::{
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
/// An implementation of the FROST P-256 SHA-256 ciphersuite scalar field.
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
}

#[derive(Clone, Copy, PartialEq)]
/// An implementation of the FROST P-256 ciphersuite group.
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

    fn order() -> <Self::Field as Field>::Scalar {
        // TODO: rethink this, no way to represent the order in `Scalar`
        Scalar::zero()
    }

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
            Some(point) => Ok(ProjectivePoint::from(point)),
            None => Err(Error::MalformedElement),
        }
    }
}

/// Context string from the ciphersuite in the [spec]
///
/// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.txt
const CONTEXT_STRING: &str = "FROST-P256-SHA256";

#[derive(Clone, Copy, PartialEq)]
/// An implementation of the FROST ciphersuite FROST(P-256, SHA-256).
pub struct P256Sha256;

impl Ciphersuite for P256Sha256 {
    type Group = P256Group;

    type HashOutput = [u8; 32];

    type SignatureSerialization = [u8; 65];

    /// H1 for FROST(P-256, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.html#name-frostp-256-sha-256
    fn H1(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let mut u = [P256ScalarField::zero()];
        let dst = CONTEXT_STRING.to_owned() + "rho";
        hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&vec![m], dst.as_bytes(), &mut u)
            .expect("should never return error according to error cases described in ExpandMsgXmd");
        u[0]
    }

    /// H2 for FROST(P-256, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.html#name-frostp-256-sha-256
    fn H2(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let mut u = [P256ScalarField::zero()];
        let dst = CONTEXT_STRING.to_owned() + "chal";
        hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&vec![m], dst.as_bytes(), &mut u)
            .expect("should never return error according to error cases described in ExpandMsgXmd");
        u[0]
    }

    /// H3 for FROST(P-256, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.html#name-frostp-256-sha-256
    fn H3(m: &[u8]) -> Self::HashOutput {
        let h = Sha256::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("digest")
            .chain(m);

        let mut output = [0u8; 32];
        output.copy_from_slice(h.finalize().as_slice());
        output
    }
}

// Shorthand alias for the ciphersuite
type P = P256Sha256;

///
pub mod keys {
    use super::*;

    ///
    pub fn keygen_with_dealer<RNG: RngCore + CryptoRng>(
        num_signers: u8,
        threshold: u8,
        mut rng: RNG,
    ) -> Result<(Vec<SharePackage>, PublicKeyPackage), &'static str> {
        frost::keys::keygen_with_dealer(num_signers, threshold, &mut rng)
    }

    ///
    pub type SharePackage = frost::keys::SharePackage<P>;

    ///
    pub type KeyPackage = frost::keys::KeyPackage<P>;

    ///
    pub type PublicKeyPackage = frost::keys::PublicKeyPackage<P>;
}

///
pub mod round1 {
    use super::*;
    ///
    pub type SigningNonces = frost::round1::SigningNonces<P>;

    ///
    pub type SigningCommitments = frost::round1::SigningCommitments<P>;

    ///
    pub fn commit<RNG>(
        participant_index: u16,
        rng: &mut RNG,
    ) -> (Vec<SigningNonces>, Vec<SigningCommitments>)
    where
        RNG: CryptoRng + RngCore,
    {
        frost::round1::commit::<P, RNG>(participant_index, rng)
    }
}

///
pub type SigningPackage = frost::SigningPackage<P>;

///
pub mod round2 {
    use super::*;

    ///
    pub type SignatureShare = frost::round2::SignatureShare<P>;

    ///
    pub type SigningPackage = frost::SigningPackage<P>;

    ///
    pub fn sign(
        signing_package: &SigningPackage,
        signer_nonces: &round1::SigningNonces,
        key_package: &keys::KeyPackage,
    ) -> Result<SignatureShare, &'static str> {
        frost::round2::sign(&signing_package, signer_nonces, key_package)
    }
}

///
pub type Signature = frost_core::Signature<P>;

///
pub fn aggregate(
    signing_package: &round2::SigningPackage,
    signature_shares: &[round2::SignatureShare],
    pubkeys: &keys::PublicKeyPackage,
) -> Result<Signature, &'static str> {
    frost::aggregate(&signing_package, &signature_shares[..], &pubkeys)
}

///
pub type SigningKey = frost_core::SigningKey<P>;

///
pub type VerifyingKey = frost_core::VerifyingKey<P>;
