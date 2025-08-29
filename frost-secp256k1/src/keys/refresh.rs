//! Refresh Shares
//!
//! Refer to [`frost_core::keys::refresh`] for more details.

use crate::{
    frost,
    keys::dkg::{round1, round2},
    Ciphersuite, CryptoRng, Error, Identifier, RngCore,
};
use alloc::{collections::btree_map::BTreeMap, vec::Vec};

use super::{KeyPackage, PublicKeyPackage, SecretShare};

/// Refer to [`frost_core::keys::refresh::compute_refreshing_shares`].
pub fn compute_refreshing_shares<C: Ciphersuite, R: RngCore + CryptoRng>(
    old_pub_key_package: PublicKeyPackage,
    max_signers: u16,
    min_signers: u16,
    identifiers: &[Identifier],
    mut rng: &mut R,
) -> Result<(Vec<SecretShare>, PublicKeyPackage), Error> {
    frost::keys::refresh::compute_refreshing_shares(
        old_pub_key_package,
        max_signers,
        min_signers,
        identifiers,
        &mut rng,
    )
}

/// Refer to [`frost_core::keys::refresh::refresh_share`].
pub fn refresh_share<C: Ciphersuite>(
    zero_share: SecretShare,
    current_share: &KeyPackage,
) -> Result<KeyPackage, Error> {
    frost::keys::refresh::refresh_share(zero_share, current_share)
}

/// Refer to [`frost_core::keys::refresh::refresh_dkg_part_1`].
pub fn refresh_dkg_part1<R: RngCore + CryptoRng>(
    identifier: Identifier,
    max_signers: u16,
    min_signers: u16,
    mut rng: R,
) -> Result<(round1::SecretPackage, round1::Package), Error> {
    frost::keys::refresh::refresh_dkg_part_1(identifier, max_signers, min_signers, &mut rng)
}

/// Refer to [`frost_core::keys::refresh::refresh_dkg_part2`].
pub fn refresh_dkg_part2(
    secret_package: round1::SecretPackage,
    round1_packages: &BTreeMap<Identifier, round1::Package>,
) -> Result<(round2::SecretPackage, BTreeMap<Identifier, round2::Package>), Error> {
    frost::keys::refresh::refresh_dkg_part2(secret_package, round1_packages)
}

/// Refer to [`frost_core::keys::refresh::refresh_dkg_shares`].
pub fn refresh_dkg_shares(
    round2_secret_package: &round2::SecretPackage,
    round1_packages: &BTreeMap<Identifier, round1::Package>,
    round2_packages: &BTreeMap<Identifier, round2::Package>,
    old_pub_key_package: PublicKeyPackage,
    old_key_package: KeyPackage,
) -> Result<(KeyPackage, PublicKeyPackage), Error> {
    frost::keys::refresh::refresh_dkg_shares(
        round2_secret_package,
        round1_packages,
        round2_packages,
        old_pub_key_package,
        old_key_package,
    )
}
