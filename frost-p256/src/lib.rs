#![allow(non_snake_case)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use elliptic_curve::hash2curve::{hash_to_field, ExpandMsgXmd};
use hex::FromHex;
use p256::{
    elliptic_curve::{
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
/// An implementation of the FROST ciphersuite scalar field.
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
        // [`curve25519_dalek::scalar::Scalar`]'s Eq/PartialEq does a constant-time comparison using
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

/// Wrapper for [`p256::EncodedPoint`].
#[derive(Default)]
pub struct P256Serialization(p256::EncodedPoint);

impl AsRef<p256::EncodedPoint> for P256Serialization {
    fn as_ref(&self) -> &p256::EncodedPoint {
        &self.0
    }
}

impl From<p256::EncodedPoint> for P256Serialization {
    fn from(encoded_point: p256::EncodedPoint) -> Self {
        Self(encoded_point)
    }
}

impl FromHex for P256Serialization {
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let data = hex::decode(hex).map_err(|_| "hex decode error")?;
        Ok(p256::EncodedPoint::from_bytes(data)
            .map_err(|_| "point decode error")?
            .into())
    }
}

impl AsRef<[u8]> for P256Serialization {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<Vec<u8>> for P256Serialization {
    type Error = &'static str;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(p256::EncodedPoint::from_bytes(data)
            .map_err(|_| "point decode error")?
            .into())
    }
}

#[derive(Clone, Copy, PartialEq)]
/// An implementation of the FROST ciphersuite group.
pub struct P256Group;

impl Group for P256Group {
    type Field = P256ScalarField;

    type Element = ProjectivePoint;

    type Serialization = P256Serialization;

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
        element.to_affine().to_encoded_point(true).into()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, Error> {
        match Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&buf.0)) {
            Some(point) => Ok(ProjectivePoint::from(point).into()),
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
        hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&vec![m], dst.as_bytes(), &mut u).unwrap();
        u[0]
    }

    /// H2 for FROST(P-256, SHA-256)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.html#name-frostp-256-sha-256
    fn H2(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let mut u = [P256ScalarField::zero()];
        let dst = CONTEXT_STRING.to_owned() + "chal";
        hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&vec![m], dst.as_bytes(), &mut u).unwrap();
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

type R = P256Sha256;

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
    pub type SharePackage = frost::keys::SharePackage<R>;

    ///
    pub type KeyPackage = frost::keys::KeyPackage<R>;

    ///
    pub type PublicKeyPackage = frost::keys::PublicKeyPackage<R>;
}

///
pub mod round1 {
    use super::*;
    ///
    pub type SigningNonces = frost::round1::SigningNonces<R>;

    ///
    pub type SigningCommitments = frost::round1::SigningCommitments<R>;

    ///
    pub fn preprocess<RNG>(
        num_nonces: u8,
        participant_index: u16,
        rng: &mut RNG,
    ) -> (Vec<SigningNonces>, Vec<SigningCommitments>)
    where
        RNG: CryptoRng + RngCore,
    {
        frost::round1::preprocess::<R, RNG>(num_nonces, participant_index, rng)
    }
}

///
pub type SigningPackage = frost::SigningPackage<R>;

///
pub mod round2 {
    use super::*;

    ///
    pub type SignatureShare = frost::round2::SignatureShare<R>;

    ///
    pub type SigningPackage = frost::SigningPackage<R>;

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
pub type Signature = frost_core::Signature<R>;

///
pub fn aggregate(
    signing_package: &round2::SigningPackage,
    signature_shares: &[round2::SignatureShare],
    pubkeys: &keys::PublicKeyPackage,
) -> Result<Signature, &'static str> {
    frost::aggregate(&signing_package, &signature_shares[..], &pubkeys)
}

///
pub type SigningKey = frost_core::SigningKey<R>;

///
pub type VerifyingKey = frost_core::VerifyingKey<R>;
