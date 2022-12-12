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

use frost_core::{frost, Ciphersuite, Field, FieldError, Group, GroupError};

#[cfg(test)]
mod tests;

/// An error.
pub type Error = frost_core::Error<Ristretto255Sha512>;

#[derive(Clone, Copy)]
/// An implementation of the FROST(ristretto255, SHA-512) ciphersuite scalar field.
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

    fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, FieldError> {
        // [`curve25519_dalek::scalar::Scalar`]'s Eq/PartialEq does a constant-time comparison using
        // `ConstantTimeEq`
        if *scalar == <Self as Field>::zero() {
            Err(FieldError::InvalidZeroScalar)
        } else {
            Ok(scalar.invert())
        }
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Scalar::random(rng)
    }

    fn serialize(scalar: &Self::Scalar) -> Self::Serialization {
        scalar.to_bytes()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, FieldError> {
        match Scalar::from_canonical_bytes(*buf) {
            Some(s) => Ok(s),
            None => Err(FieldError::MalformedScalar),
        }
    }

    fn little_endian_serialize(scalar: &Self::Scalar) -> Self::Serialization {
        Self::serialize(scalar)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// An implementation of the FROST(ristretto255, SHA-512) ciphersuite group.
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

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, GroupError> {
        match CompressedRistretto::from_slice(buf.as_ref()).decompress() {
            Some(point) => {
                if point == Self::identity() {
                    Err(GroupError::InvalidIdentityElement)
                } else {
                    Ok(point)
                }
            }
            None => Err(GroupError::MalformedElement),
        }
    }
}

/// Context string from the ciphersuite in the [spec].
///
/// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-6.2-1
const CONTEXT_STRING: &str = "FROST-RISTRETTO255-SHA512-v11";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
/// An implementation of the FROST(ristretto255, SHA-512) ciphersuite.
pub struct Ristretto255Sha512;

impl Ciphersuite for Ristretto255Sha512 {
    type Group = RistrettoGroup;

    type HashOutput = [u8; 64];

    type SignatureSerialization = [u8; 64];

    /// H1 for FROST(ristretto255, SHA-512)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-6.2-2.2.2.1
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
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-6.2-2.2.2.2
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
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-6.2-2.2.2.3
    fn H3(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("nonce")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        <<Self::Group as Group>::Field as Field>::Scalar::from_bytes_mod_order_wide(&output)
    }

    /// H4 for FROST(ristretto255, SHA-512)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-6.2-2.2.2.4
    fn H4(m: &[u8]) -> Self::HashOutput {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("msg")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        output
    }

    /// H5 for FROST(ristretto255, SHA-512)
    ///
    /// [spec]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-6.2-2.2.2.5
    fn H5(m: &[u8]) -> Self::HashOutput {
        let h = Sha512::new()
            .chain(CONTEXT_STRING.as_bytes())
            .chain("com")
            .chain(m);

        let mut output = [0u8; 64];
        output.copy_from_slice(h.finalize().as_slice());
        output
    }

    /// HDKG for FROST(ristretto255, SHA-512)
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

type R = Ristretto255Sha512;

/// A FROST(ristretto255, SHA-512) participant identifier.
pub type Identifier = frost::Identifier<R>;

/// FROST(ristretto255, SHA-512) keys, key generation, key shares.
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
    /// To derive a FROST(ristretto255, SHA-512) keypair, the receiver of the [`SecretShare`] *must* call
    /// .into(), which under the hood also performs validation.
    pub type SecretShare = frost::keys::SecretShare<R>;

    /// A FROST(ristretto255, SHA-512) keypair, which can be generated either by a trusted dealer or using
    /// a DKG.
    ///
    /// When using a central dealer, [`SecretShare`]s are distributed to
    /// participants, who then perform verification, before deriving
    /// [`KeyPackage`]s, which they store to later use during signing.
    pub type KeyPackage = frost::keys::KeyPackage<R>;

    /// Public data that contains all the signers' public keys as well as the
    /// group public key.
    ///
    /// Used for verification purposes before publishing a signature.
    pub type PublicKeyPackage = frost::keys::PublicKeyPackage<R>;

    pub mod dkg {
        #![doc = include_str!("../dkg.md")]
        use super::*;

        /// The secret package that must be kept in memory by the participant
        /// between the first and second parts of the DKG protocol (round 1).
        ///
        /// # Security
        ///
        /// This package MUST NOT be sent to other participants!
        pub type Round1SecretPackage = frost::keys::dkg::Round1SecretPackage<R>;

        /// The package that must be broadcast by each participant to all other participants
        /// between the first and second parts of the DKG protocol (round 1).
        pub type Round1Package = frost::keys::dkg::Round1Package<R>;

        /// The secret package that must be kept in memory by the participant
        /// between the second and third parts of the DKG protocol (round 2).
        ///
        /// # Security
        ///
        /// This package MUST NOT be sent to other participants!
        pub type Round2SecretPackage = frost::keys::dkg::Round2SecretPackage<R>;

        /// A package that must be sent by each participant to some other participants
        /// in Round 2 of the DKG protocol. Note that there is one specific package
        /// for each specific recipient, in contrast to Round 1.
        ///
        /// # Security
        ///
        /// The package must be sent on an *confidential* and *authenticated* channel.
        pub type Round2Package = frost::keys::dkg::Round2Package<R>;

        /// Performs the first part of the distributed key generation protocol
        /// for the given participant.
        ///
        /// It returns the [`Round1SecretPackage`] that must be kept in memory
        /// by the participant for the other steps, and the [`Round1Package`] that
        /// must be sent to other participants.
        pub fn keygen_part1<R: RngCore + CryptoRng>(
            identifier: Identifier,
            max_signers: u16,
            min_signers: u16,
            mut rng: R,
        ) -> Result<(Round1SecretPackage, Round1Package), Error> {
            frost::keys::dkg::keygen_part1(identifier, max_signers, min_signers, &mut rng)
        }

        /// Performs the second part of the distributed key generation protocol
        /// for the participant holding the given [`Round1SecretPackage`],
        /// given the received [`Round1Package`]s received from the other participants.
        ///
        /// It returns the [`Round2SecretPackage`] that must be kept in memory
        /// by the participant for the final step, and the [`Round2Package`]s that
        /// must be sent to other participants.
        pub fn keygen_part2(
            secret_package: Round1SecretPackage,
            round1_packages: &[Round1Package],
        ) -> Result<(Round2SecretPackage, Vec<Round2Package>), Error> {
            frost::keys::dkg::keygen_part2(secret_package, round1_packages)
        }

        /// Performs the third and final part of the distributed key generation protocol
        /// for the participant holding the given [`Round2SecretPackage`],
        /// given the received [`Round1Package`]s and [`Round2Package`]s received from
        /// the other participants.
        ///
        /// It returns the [`KeyPackage`] that has the long-lived key share for the
        /// participant, and the [`PublicKeyPackage`]s that has public information
        /// about all participants; both of which are required to compute FROST
        /// signatures.
        pub fn keygen_part3(
            round2_secret_package: &Round2SecretPackage,
            round1_packages: &[Round1Package],
            round2_packages: &[Round2Package],
        ) -> Result<(KeyPackage, PublicKeyPackage), Error> {
            frost::keys::dkg::keygen_part3(round2_secret_package, round1_packages, round2_packages)
        }
    }
}

/// FROST(ristretto255, SHA-512) Round 1 functionality and types.
pub mod round1 {
    use frost_core::frost::keys::SigningShare;

    use super::*;

    /// Comprised of FROST(ristretto255, SHA-512) hiding and binding nonces.
    ///
    /// Note that [`SigningNonces`] must be used *only once* for a signing
    /// operation; re-using nonces will result in leakage of a signer's long-lived
    /// signing key.
    pub type SigningNonces = frost::round1::SigningNonces<R>;

    /// Published by each participant in the first round of the signing protocol.
    ///
    /// This step can be batched if desired by the implementation. Each
    /// SigningCommitment can be used for exactly *one* signature.
    pub type SigningCommitments = frost::round1::SigningCommitments<R>;

    /// Performed once by each participant selected for the signing operation.
    ///
    /// Generates the signing nonces and commitments to be used in the signing
    /// operation.
    pub fn commit<RNG>(
        participant_identifier: frost::Identifier<R>,
        secret: &SigningShare<R>,
        rng: &mut RNG,
    ) -> (SigningNonces, SigningCommitments)
    where
        RNG: CryptoRng + RngCore,
    {
        frost::round1::commit::<R, RNG>(participant_identifier, secret, rng)
    }
}

/// Generated by the coordinator of the signing operation and distributed to
/// each signing party.
pub type SigningPackage = frost::SigningPackage<R>;

/// FROST(ristretto255, SHA-512) Round 2 functionality and types, for signature share generation.
pub mod round2 {
    use super::*;

    /// A FROST(ristretto255, SHA-512) participant's signature share, which the Coordinator will aggregate with all other signer's
    /// shares into the joint signature.
    pub type SignatureShare = frost::round2::SignatureShare<R>;

    /// Generated by the coordinator of the signing operation and distributed to
    /// each signing party
    pub type SigningPackage = frost::SigningPackage<R>;

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

/// A Schnorr signature on FROST(ristretto255, SHA-512).
pub type Signature = frost_core::Signature<R>;

/// Verifies each FROST(ristretto255, SHA-512) participant's signature share, and if all are valid,
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

/// A signing key for a Schnorr signature on FROST(ristretto255, SHA-512).
pub type SigningKey = frost_core::SigningKey<R>;

/// A valid verifying key for Schnorr signatures on FROST(ristretto255, SHA-512).
pub type VerifyingKey = frost_core::VerifyingKey<R>;
