#![allow(non_snake_case)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::Identity,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{digest::Update, Digest, Sha512};

use frost_core::{frost, Ciphersuite, Field, Group};

#[cfg(test)]
mod tests;

pub use frost_core::Error;

/// An implementation of the FROST(Ed25519, SHA-512) ciphersuite scalar field.
pub type Ed25519ScalarField = frost_ristretto255::RistrettoScalarField;

#[derive(Clone, Copy, PartialEq, Eq)]
/// An implementation of the FROST(Ed25519, SHA-512) ciphersuite group.
pub struct Ed25519Group;

impl Group for Ed25519Group {
    type Field = Ed25519ScalarField;

    type Element = EdwardsPoint;

    type Serialization = [u8; 32];

    fn cofactor() -> <Self::Field as Field>::Scalar {
        Scalar::one()
    }

    fn identity() -> Self::Element {
        EdwardsPoint::identity()
    }

    fn generator() -> Self::Element {
        ED25519_BASEPOINT_POINT
    }

    fn serialize(element: &Self::Element) -> Self::Serialization {
        element.compress().to_bytes()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, Error> {
        match CompressedEdwardsY::from_slice(buf.as_ref()).decompress() {
            Some(point) => {
                if point == Self::identity() {
                    Err(Error::InvalidIdentityElement)
                } else if point.is_torsion_free() {
                    Ok(point)
                } else {
                    Err(Error::InvalidNonPrimeOrderElement)
                }
            }
            None => Err(Error::MalformedElement),
        }
    }
}

/// Context string 'FROST-RISTRETTO255-SHA512-v5' from the ciphersuite in the [spec]
///
/// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-10.html#section-6.1-1
const CONTEXT_STRING: &str = "FROST-ED25519-SHA512-v11";

#[derive(Clone, Copy, PartialEq, Eq)]
/// An implementation of the FROST(Ed25519, SHA-512) ciphersuite.
pub struct Ed25519Sha512;

impl Ciphersuite for Ed25519Sha512 {
    type Group = Ed25519Group;

    type HashOutput = [u8; 64];

    type SignatureSerialization = [u8; 64];

    /// H1 for FROST(Ed25519, SHA-512)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-10.html#section-6.1-2.2.2.1
    fn H1(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("rho")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        <<Self::Group as Group>::Field as Field>::Scalar::from_bytes_mod_order_wide(&output)
    }

    /// H2 for FROST(Ed25519, SHA-512)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-10.html#section-6.1-2.2.2.2
    fn H2(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let h = Sha512::new().chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        <<Self::Group as Group>::Field as Field>::Scalar::from_bytes_mod_order_wide(&output)
    }

    /// H3 for FROST(Ed25519, SHA-512)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-10.html#section-6.1-2.2.2.3
    fn H3(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("nonce")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        <<Self::Group as Group>::Field as Field>::Scalar::from_bytes_mod_order_wide(&output)
    }

    /// H4 for FROST(Ed25519, SHA-512)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-10.html#section-6.1-2.2.2.4
    fn H4(m: &[u8]) -> Self::HashOutput {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("msg")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        output
    }

    /// H5 for FROST(Ed25519, SHA-512)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-10.html#section-6.1-2.2.2.5
    fn H5(m: &[u8]) -> Self::HashOutput {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("com")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        output
    }

    /// HDKG for FROST(Ed25519, SHA-512)
    fn HDKG(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("dkg")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        Some(<<Self::Group as Group>::Field as Field>::Scalar::from_bytes_mod_order_wide(&output))
    }
}

type E = Ed25519Sha512;

/// A FROST(Ed25519, SHA-512) participant identifier.
pub type Identifier = frost::Identifier<E>;

/// FROST(Ed25519, SHA-512) keys, key generation, key shares.
pub mod keys {
    use super::*;

    /// Allows all participants' keys to be generated using a central, trusted
    /// dealer.
    pub fn keygen_with_dealer<RNG: RngCore + CryptoRng>(
        num_signers: u8,
        threshold: u8,
        mut rng: RNG,
    ) -> Result<(Vec<SecretShare>, PublicKeyPackage), &'static str> {
        frost::keys::keygen_with_dealer(num_signers, threshold, &mut rng)
    }

    /// Secret and public key material generated by a dealer performing
    /// [`keygen_with_dealer`].
    ///
    /// # Security
    ///
    /// To derive a FROST(Ed25519, SHA-512) keypair, the receiver of the [`SecretShare`] *must* call
    /// .into(), which under the hood also performs validation.
    pub type SecretShare = frost::keys::SecretShare<E>;

    /// A FROST(Ed25519, SHA-512) keypair, which can be generated either by a trusted dealer or using
    /// a DKG.
    ///
    /// When using a central dealer, [`SecretShare`]s are distributed to
    /// participants, who then perform verification, before deriving
    /// [`KeyPackage`]s, which they store to later use during signing.
    pub type KeyPackage = frost::keys::KeyPackage<E>;

    /// Public data that contains all the signers' public keys as well as the
    /// group public key.
    ///
    /// Used for verification purposes before publishing a signature.
    pub type PublicKeyPackage = frost::keys::PublicKeyPackage<E>;
}

/// FROST(Ed25519, SHA-512) Round 1 functionality and types.
pub mod round1 {
    use frost_core::frost::keys::SigningShare;

    use super::*;

    /// Comprised of FROST(Ed25519, SHA-512) hiding and binding nonces.
    ///
    /// Note that [`SigningNonces`] must be used *only once* for a signing
    /// operation; re-using nonces will result in leakage of a signer's long-lived
    /// signing key.
    pub type SigningNonces = frost::round1::SigningNonces<E>;

    /// Published by each participant in the first round of the signing protocol.
    ///
    /// This step can be batched if desired by the implementation. Each
    /// SigningCommitment can be used for exactly *one* signature.
    pub type SigningCommitments = frost::round1::SigningCommitments<E>;

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Generates the signing nonces and commitments to be used in the signing
    /// operation.
    pub fn commit<RNG>(
        participant_identifier: frost::Identifier<E>,
        secret: &SigningShare<E>,
        rng: &mut RNG,
    ) -> (SigningNonces, SigningCommitments)
    where
        RNG: CryptoRng + RngCore,
    {
        frost::round1::commit::<E, RNG>(participant_identifier, secret, rng)
    }
}

/// Generated by the coordinator of the signing operation and distributed to
/// each signing party.
pub type SigningPackage = frost::SigningPackage<E>;

/// FROST(Ed25519, SHA-512) Round 2 functionality and types, for signature share generation.
pub mod round2 {
    use super::*;

    /// A FROST(Ed25519, SHA-512) participant's signature share, which the Coordinator will aggregate with all other signer's
    /// shares into the joint signature.
    pub type SignatureShare = frost::round2::SignatureShare<E>;

    /// Generated by the coordinator of the signing operation and distributed to
    /// each signing party
    pub type SigningPackage = frost::SigningPackage<E>;

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
    ) -> Result<SignatureShare, &'static str> {
        frost::round2::sign(signing_package, signer_nonces, key_package)
    }
}

/// A Schnorr signature on FROST(Ed25519, SHA-512).
pub type Signature = frost_core::Signature<E>;

/// Verifies each FROST(Ed25519, SHA-512) participant's signature share, and if all are valid,
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
) -> Result<Signature, &'static str> {
    frost::aggregate(signing_package, signature_shares, pubkeys)
}

/// A signing key for a Schnorr signature on FROST(Ed25519, SHA-512).
pub type SigningKey = frost_core::SigningKey<E>;

/// A valid verifying key for Schnorr signatures on FROST(Ed25519, SHA-512).
pub type VerifyingKey = frost_core::VerifyingKey<E>;
