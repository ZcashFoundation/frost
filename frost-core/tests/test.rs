#![allow(non_snake_case)]

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, digest::Update, ristretto::RistrettoPoint,
    scalar::Scalar, traits::Identity,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use frost_core::{Ciphersuite, Group, Thing};

pub struct RistrettoGroup;

impl Group for RistrettoGroup {
    type Scalar = Scalar;

    type Element = RistrettoPoint;

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
}

/// Context string 'FROST-RISTRETTO255-SHA512' from the ciphersuite in the [spec]
///
/// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.txt
const CONTEXT_STRING: &str = "FROST-RISTRETTO255-SHA512";

pub struct Ristretto255Sha512;

impl Ciphersuite for Ristretto255Sha512 {
    type Group = RistrettoGroup;

    type HashOutput = [u8; 64];

    /// H1 for FROST(ristretto255, SHA-512)
    ///
    /// [spec]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash
    fn H1(m: &[u8]) -> Self::HashOutput {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("rho")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        output
    }

    /// H2 for FROST(ristretto255, SHA-512)
    ///
    /// [spec]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash-function-dep-hash
    fn H2(m: &[u8]) -> Self::HashOutput {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("chal")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        output
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

    /// Generates the challenge as is required for Schnorr signatures.
    ///
    /// Deals in bytes, so that [FROST] and singleton signing and verification can use it with different
    /// types.
    ///
    /// This is the only invocation of the H2 hash function from the [RFC].
    ///
    /// [FROST]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-03.html#section-4.6
    /// [RFC]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-03.html#section-3.2
    fn challenge(
        R_bytes: &[u8; 32],
        pubkey_bytes: &[u8; 32],
        msg: &[u8],
    ) -> <Self::Group as frost_core::Group>::Scalar {
        let mut preimage = vec![];

        preimage.extend_from_slice(R_bytes);
        preimage.extend_from_slice(pubkey_bytes);
        preimage.extend_from_slice(msg);

        let challenge_wide = Self::H2(&preimage[..]);

        Scalar::from_bytes_mod_order_wide(&challenge_wide)
    }
}

pub mod ristretto {

    use super::*;

    pub type RistrettoThing = Thing<Ristretto255Sha512>;
}

#[test]
fn use_parameterized_types() {
    let h3_image = Ristretto255Sha512::H3(b"test_message");

    println!("h3_image: {:?}", h3_image);

    let thing = ristretto::RistrettoThing::default();
}
