use super::*;
use alloc::{collections::BTreeMap, vec::Vec};

pub use frost::keys::cocktail_dkg::CocktailCiphersuite;

/// COCKTAIL-DKG Round 1 structures.
pub mod round1 {
    use super::*;

    /// The secret package that must be kept in memory by the participant
    /// between Round 1 and Round 2 of the COCKTAIL-DKG protocol.
    ///
    /// # Security
    ///
    /// This package MUST NOT be sent to other participants!
    pub type SecretPackage = frost::keys::cocktail_dkg::round1::SecretPackage<R>;

    /// The package that must be broadcast by each participant to all other participants
    /// (via the coordinator) between Round 1 and Round 2.
    pub type Package = frost::keys::cocktail_dkg::round1::Package<R>;
}

/// COCKTAIL-DKG Round 2 structures.
pub mod round2 {
    use super::*;

    /// The secret package that must be kept in memory by the participant
    /// between Round 2 and Round 3 of the COCKTAIL-DKG protocol.
    ///
    /// # Security
    ///
    /// This package MUST NOT be sent to other participants!
    pub type SecretPackage = frost::keys::cocktail_dkg::round2::SecretPackage<R>;

    /// The package sent by each participant to the coordinator after Round 2,
    /// containing the transcript signature.
    pub type Package = frost::keys::cocktail_dkg::round2::Package<R>;
}

/// Performs Round 1 of the COCKTAIL-DKG protocol for the given participant.
#[allow(clippy::too_many_arguments)]
pub fn part1<RNG: RngCore + CryptoRng>(
    identifier: Identifier,
    max_signers: u16,
    min_signers: u16,
    static_signing_key: &SigningKey,
    participants: &BTreeMap<Identifier, VerifyingKey>,
    context: &[u8],
    payloads: &BTreeMap<Identifier, Vec<u8>>,
    rng: RNG,
) -> Result<(round1::SecretPackage, round1::Package), Error> {
    frost::keys::cocktail_dkg::part1(
        identifier,
        max_signers,
        min_signers,
        static_signing_key,
        participants,
        context,
        payloads,
        rng,
    )
}

/// Performs Round 2 of the COCKTAIL-DKG protocol.
#[allow(clippy::type_complexity)]
pub fn part2<RNG: RngCore + CryptoRng>(
    secret_package: round1::SecretPackage,
    round1_packages: &BTreeMap<Identifier, round1::Package>,
    static_signing_key: &SigningKey,
    participants: &BTreeMap<Identifier, VerifyingKey>,
    context: &[u8],
    extension: &[u8],
    rng: RNG,
) -> Result<
    (
        round2::SecretPackage,
        round2::Package,
        BTreeMap<Identifier, Vec<u8>>,
    ),
    Error,
> {
    frost::keys::cocktail_dkg::part2(
        secret_package,
        round1_packages,
        static_signing_key,
        participants,
        context,
        extension,
        rng,
    )
}

/// Performs Round 3 (CertEq) of the COCKTAIL-DKG protocol.
#[allow(clippy::type_complexity)]
pub fn part3(
    secret_package: &round2::SecretPackage,
    round2_packages: &BTreeMap<Identifier, round2::Package>,
) -> Result<
    (
        KeyPackage,
        PublicKeyPackage,
        Vec<u8>,
        BTreeMap<Identifier, Signature>,
    ),
    Error,
> {
    frost::keys::cocktail_dkg::part3(secret_package, round2_packages)
}

/// Recovers a participant's DKG outputs from the static secret key, transcript,
/// success certificate, and ciphertexts.
pub fn recover(
    static_signing_key: &SigningKey,
    transcript: &[u8],
    success_certificate: &BTreeMap<Identifier, Signature>,
    ciphertexts: &BTreeMap<Identifier, Vec<u8>>,
) -> Result<(KeyPackage, PublicKeyPackage), Error> {
    frost::keys::cocktail_dkg::recover(
        static_signing_key,
        transcript,
        success_certificate,
        ciphertexts,
    )
}
