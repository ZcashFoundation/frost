#![doc = include_str!("../../dkg.md")]
use super::*;

/// The secret package that must be kept in memory by the participant
/// between the first and second parts of the DKG protocol (round 1).
///
/// # Security
///
/// This package MUST NOT be sent to other participants!
pub type Round1SecretPackage = frost::keys::dkg::Round1SecretPackage<P>;

/// The package that must be broadcast by each participant to all other participants
/// between the first and second parts of the DKG protocol (round 1).
pub type Round1Package = frost::keys::dkg::Round1Package<P>;

/// The secret package that must be kept in memory by the participant
/// between the second and third parts of the DKG protocol (round 2).
///
/// # Security
///
/// This package MUST NOT be sent to other participants!
pub type Round2SecretPackage = frost::keys::dkg::Round2SecretPackage<P>;

/// A package that must be sent by each participant to some other participants
/// in Round 2 of the DKG protocol. Note that there is one specific package
/// for each specific recipient, in contrast to Round 1.
///
/// # Security
///
/// The package must be sent on an *confidential* and *authenticated* channel.
pub type Round2Package = frost::keys::dkg::Round2Package<P>;

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
