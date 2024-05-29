//! Test for Refreshing shares

use std::collections::BTreeMap;

use rand_core::{CryptoRng, RngCore};

use crate::{self as frost};
use crate::{
    keys::{refresh::refresh_shares_with_dealer, PublicKeyPackage, SecretShare},
    Ciphersuite, Error, Identifier, SigningKey,
};

use super::ciphersuite_generic::check_sign;

/// We want to test that recover share matches the original share
pub fn check_refresh_shares_with_dealer<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    // Compute shares

    ////////////////////////////////////////////////////////////////////////////
    // Old Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;
    let (old_shares, pub_key_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();

    // Try to refresh shares
    // Signer 2 will be removed and Signers 1, 3, 4 & 5 will remain

    ////////////////////////////////////////////////////////////////////////////
    // New Key generation
    ////////////////////////////////////////////////////////////////////////////

    let remaining_ids = vec![
        Identifier::try_from(1).unwrap(),
        Identifier::try_from(3).unwrap(),
        Identifier::try_from(4).unwrap(),
        Identifier::try_from(5).unwrap(),
    ];

    const NEW_MAX_SIGNERS: u16 = 4;

    let (shares, new_pub_key_package) = refresh_shares_with_dealer(
        old_shares,
        pub_key_package,
        NEW_MAX_SIGNERS,
        min_signers,
        &remaining_ids,
        &mut rng,
    )
    .unwrap();

    let mut key_packages: BTreeMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> =
        BTreeMap::new();

    for (k, v) in shares {
        let key_package = frost::keys::KeyPackage::try_from(v).unwrap();
        key_packages.insert(k, key_package);
    }
    check_sign(min_signers, key_packages, rng, new_pub_key_package).unwrap();
}

/// Check refesh shares with dealer errors
pub fn check_refresh_shares_with_dealer_fails_with_invalid_signers<
    C: Ciphersuite,
    R: RngCore + CryptoRng,
>(
    new_max_signers: u16,
    min_signers: u16,
    identifiers: &[Identifier<C>],
    error: Error<C>,
    mut rng: R,
) {
    let (old_shares, pub_key_package) = build_old_shares::<C, R>(5, 2, &mut rng);
    let out = refresh_shares_with_dealer(
        old_shares,
        pub_key_package,
        new_max_signers,
        min_signers,
        identifiers,
        &mut rng,
    );

    assert!(out.is_err());
    assert!(out == Err(error))
}

fn build_old_shares<C: Ciphersuite, R: RngCore + CryptoRng>(
    max_signers: u16,
    min_signers: u16,
    mut rng: &mut R,
) -> (BTreeMap<Identifier<C>, SecretShare<C>>, PublicKeyPackage<C>) {
    // Compute shares

    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let mut bytes = [0; 64];
    rng.fill_bytes(&mut bytes);

    let key = SigningKey::new(&mut rng);

    let (old_shares, pub_key_package): (
        BTreeMap<Identifier<C>, SecretShare<C>>,
        PublicKeyPackage<C>,
    ) = frost::keys::split(
        &key,
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();

    // Try to refresh shares
    // Signer 2 will be removed and Signers 1, 3, 4 & 5 will remain

    // Rerun key generation

    (old_shares, pub_key_package)
}
