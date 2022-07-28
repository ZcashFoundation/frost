#![allow(non_snake_case)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{digest::Update, Digest, Sha512};

use frost_core::{frost, Ciphersuite, Field, Group};

#[cfg(test)]
mod tests;

pub use frost_core::Error;

#[derive(Clone, Copy)]
/// An implementation of the FROST ciphersuite scalar field.
pub struct RistrettoScalarField;

impl Field for RistrettoScalarField {
    type Scalar = Scalar;

    type Serialization = [u8; 32];

    fn zero() -> Self::Scalar {
        Scalar::zero()
    }

    fn one() -> Self::Scalar {
        Scalar::one()
    }

    fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, Error> {
        // [`curve25519_dalek::scalar::Scalar`]'s Eq/PartialEq does a constant-time comparison using
        // `ConstantTimeEq`
        if *scalar == <Self as Field>::zero() {
            Err(Error::InvalidZeroScalar)
        } else {
            Ok(scalar.invert())
        }
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Scalar::random(rng)
    }

    fn random_nonzero<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        loop {
            let scalar = Scalar::random(rng);

            // This impl of `Eq` calls to `ConstantTimeEq` under the hood
            if scalar != Scalar::zero() {
                return scalar;
            }
        }
    }

    fn serialize(scalar: &Self::Scalar) -> Self::Serialization {
        scalar.to_bytes()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, Error> {
        match Scalar::from_canonical_bytes(*buf) {
            Some(s) => Ok(s),
            None => Err(Error::MalformedScalar),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// An implementation of the FROST ciphersuite group.
pub struct RistrettoGroup;

impl Group for RistrettoGroup {
    type Field = RistrettoScalarField;

    type Element = RistrettoPoint;

    type Serialization = [u8; 32];

    fn cofactor() -> <Self::Field as Field>::Scalar {
        Scalar::one()
    }

    fn identity() -> Self::Element {
        RistrettoPoint::identity()
    }

    fn generator() -> Self::Element {
        RISTRETTO_BASEPOINT_POINT
    }

    fn serialize(element: &Self::Element) -> Self::Serialization {
        element.compress().to_bytes()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, Error> {
        match CompressedRistretto::from_slice(buf.as_ref()).decompress() {
            Some(point) => Ok(point),
            None => Err(Error::MalformedElement),
        }
    }
}

/// Context string 'FROST-RISTRETTO255-SHA512-v5' from the ciphersuite in the [spec]
///
/// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-05.html#section-6.2-1
const CONTEXT_STRING: &str = "FROST-RISTRETTO255-SHA512-v5";

#[derive(Clone, Copy, PartialEq, Eq)]
/// An implementation of the FROST ciphersuite Ristretto255-SHA512.
pub struct Ristretto255Sha512;

impl Ciphersuite for Ristretto255Sha512 {
    type Group = RistrettoGroup;

    type HashOutput = [u8; 64];

    type SignatureSerialization = [u8; 64];

    /// H1 for FROST(ristretto255, SHA-512)
    ///
    /// [spec]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash
    fn H1(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("rho")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        <<Self::Group as Group>::Field as Field>::Scalar::from_bytes_mod_order_wide(&output)
    }

    /// H2 for FROST(ristretto255, SHA-512)
    ///
    /// [spec]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash-function-dep-hash
    fn H2(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("chal")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        <<Self::Group as Group>::Field as Field>::Scalar::from_bytes_mod_order_wide(&output)
    }

    /// H3 for FROST(ristretto255, SHA-512)
    ///
    /// [spec]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash-function-dep-hash
    fn H3(m: &[u8]) -> Self::HashOutput {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("digest")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        output
    }

    /// H4 for FROST(ristretto255, SHA-512)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-05.html#name-frostristretto255-sha-512
    fn H4(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("nonce")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        <<Self::Group as Group>::Field as Field>::Scalar::from_bytes_mod_order_wide(&output)
    }
}

type R = Ristretto255Sha512;

///
pub type Identifier = frost::Identifier<R>;

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
    use frost_core::frost::keys::SecretShareValue;

    use super::*;
    ///
    pub type SigningNonces = frost::round1::SigningNonces<R>;

    ///
    pub type SigningCommitments = frost::round1::SigningCommitments<R>;

    ///
    pub fn commit<RNG>(
        participant_identifier: frost::Identifier<R>,
        secret: &SecretShareValue<R>,
        rng: &mut RNG,
    ) -> (SigningNonces, SigningCommitments)
    where
        RNG: CryptoRng + RngCore,
    {
        frost::round1::commit::<R, RNG>(participant_identifier, secret, rng)
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
        frost::round2::sign(signing_package, signer_nonces, key_package)
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
    frost::aggregate(signing_package, signature_shares, pubkeys)
}

///
pub type SigningKey = frost_core::SigningKey<R>;

///
pub type VerifyingKey = frost_core::VerifyingKey<R>;
