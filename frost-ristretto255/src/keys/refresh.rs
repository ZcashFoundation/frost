//! Refresh Shares
//!
//! Implements the functionality to refresh a share. This requires the participation
//! of all the remaining signers. This can be done using a Trusted Dealer or
//! DKG (not yet implemented)

use std::collections::BTreeMap;

use crate::{frost, Ciphersuite, CryptoRng, Error, Identifier, RngCore};

use super::{PublicKeyPackage, SecretShare};

/// Refresh shares using a trusted dealer
pub fn refresh_shares_with_dealer<C: Ciphersuite, R: RngCore + CryptoRng>(
    current_shares: BTreeMap<Identifier, SecretShare>,
    old_pub_key_package: PublicKeyPackage,
    max_signers: u16,
    min_signers: u16,
    identifiers: &[Identifier],
    mut rng: &mut R,
) -> Result<(BTreeMap<Identifier, SecretShare>, PublicKeyPackage), Error> {
    frost::keys::refresh::refresh_shares_with_dealer(
        current_shares,
        old_pub_key_package,
        max_signers,
        min_signers,
        identifiers,
        &mut rng,
    )
}
