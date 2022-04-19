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

use frost_core::{Ciphersuite, Error, Group};

pub struct RistrettoGroup;

impl Group for RistrettoGroup {
    type Element = RistrettoPoint;

    type Scalar = Scalar;

    type ElementSerialization = [u8; 32];

    type ScalarSerialization = [u8; 32];

    fn order() -> Self::Scalar {
        BASEPOINT_ORDER
    }

    fn cofactor() -> Self::Scalar {
        Scalar::one()
    }

    fn identity() -> Self::Element {
        RistrettoPoint::identity()
    }

    fn generator() -> Self::Element {
        RISTRETTO_BASEPOINT_POINT
    }

    fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Scalar::random(rng)
    }

    fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        loop {
            let scalar = Scalar::random(rng);

            // This impl of `Eq` calls to `ConstantTimeEq` under the hood
            if scalar != Scalar::zero() {
                return scalar;
            }
        }
    }

    fn serialize_element(element: &Self::Element) -> Self::ElementSerialization {
        element.compress().to_bytes()
    }

    fn deserialize_element(buf: &Self::ElementSerialization) -> Result<Self::Element, Error> {
        match CompressedRistretto::from_slice(buf.as_ref()).decompress() {
            Some(point) => Ok(point),
            None => Err(Error::MalformedElement),
        }
    }

    fn serialize_scalar(scalar: &Self::Scalar) -> Self::ScalarSerialization {
        scalar.to_bytes()
    }

    fn deserialize_scalar(buf: &Self::ScalarSerialization) -> Result<Self::Scalar, Error> {
        match Scalar::from_canonical_bytes(*buf) {
            Some(s) => Ok(s),
            None => Err(Error::MalformedScalar),
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
    fn H1(m: &[u8]) -> <Self::Group as Group>::Scalar {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("rho")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        <Self::Group as Group>::Scalar::from_bytes_mod_order_wide(&output)
    }

    /// H2 for FROST(ristretto255, SHA-512)
    ///
    /// [spec]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash-function-dep-hash
    fn H2(m: &[u8]) -> <Self::Group as Group>::Scalar {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("chal")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        <Self::Group as Group>::Scalar::from_bytes_mod_order_wide(&output)
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
