//! Refresh Shares
//!
//! Implements the functionality to refresh a share. This requires the participation
//! of all the remaining signers. This can be done using a Trusted Dealer or
//! DKG (not yet implemented)

use crate::{frost, Ciphersuite, CryptoRng, Error, Identifier, RngCore};
use alloc::vec::Vec;

use super::{KeyPackage, PublicKeyPackage, SecretShare};

/// Refreshes shares using a trusted dealer
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

/// Each participant refreshed their shares
pub fn refresh_share<C: Ciphersuite>(
    zero_share: SecretShare,
    current_share: &KeyPackage,
) -> Result<KeyPackage, Error> {
    frost::keys::refresh::refresh_share(zero_share, current_share)
}
