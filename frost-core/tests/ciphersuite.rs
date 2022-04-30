#![allow(non_snake_case)]

use curve25519_dalek::{
    constants::{BASEPOINT_ORDER, RISTRETTO_BASEPOINT_POINT},
    digest::Update,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use frost_core::{Ciphersuite, Error, Field, Group};

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
        // !TODO!(dconnolly): do a ct_eq with zero, failing if it is
        Ok(scalar.invert())
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

pub struct RistrettoGroup;

impl Group for RistrettoGroup {
    type Field = RistrettoScalarField;

    type Element = RistrettoPoint;

    type Serialization = [u8; 32];

    fn order() -> Self::Field::Scalar {
        BASEPOINT_ORDER
    }

    fn cofactor() -> Self::Field::Scalar {
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

/// Context string 'FROST-RISTRETTO255-SHA512' from the ciphersuite in the [spec]
///
/// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.txt
const CONTEXT_STRING: &str = "FROST-RISTRETTO255-SHA512";

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
}

#[test]
fn use_parameterized_types() {
    let h3_image = Ristretto255Sha512::H3(b"test_message");

    println!("h3_image: {:?}", h3_image);
}
