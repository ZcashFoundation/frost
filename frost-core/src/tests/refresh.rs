//! Test for Refreshing shares

use std::collections::BTreeMap;

use rand_core::{CryptoRng, RngCore};

use crate::keys::refresh::{calculate_zero_key, refresh_share};
use crate::{self as frost};
use crate::{
    keys::{KeyPackage, PublicKeyPackage, SecretShare},
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

    // Trusted Dealer generates zero keys

    let (zero_shares, new_pub_key_package) = calculate_zero_key(
        pub_key_package,
        NEW_MAX_SIGNERS,
        min_signers,
        &remaining_ids,
        &mut rng,
    )
    .unwrap();

    // Each participant refreshes their share

    let mut new_shares = BTreeMap::new();

    for i in 0..remaining_ids.len() {
        let identifier = remaining_ids[i];
        let current_share = &old_shares[&identifier];
        new_shares.insert(
            identifier,
            refresh_share(zero_shares[i].clone(), current_share),
        );
    }

    let mut key_packages: BTreeMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> =
        BTreeMap::new();

    for (k, v) in new_shares {
        let key_package = frost::keys::KeyPackage::try_from(v.unwrap()).unwrap();
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
    let (_old_shares, pub_key_package) = build_old_shares::<C, R>(5, 2, &mut rng);
    let out = calculate_zero_key(
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

/// Check serialisation
pub fn check_refresh_shares_with_dealer_serialisation<C: Ciphersuite, R: RngCore + CryptoRng>(
    mut rng: R,
) {
    // Compute shares

    ////////////////////////////////////////////////////////////////////////////
    // Old Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;
    let (_old_shares, pub_key_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();

    ////////////////////////////////////////////////////////////////////////////
    // New Key generation
    //
    // Zero key is calculated by trusted dealer
    // Signer 2 will be removed and Signers 1, 3, 4 & 5 will remain
    ////////////////////////////////////////////////////////////////////////////

    let remaining_ids = vec![
        Identifier::try_from(1).unwrap(),
        Identifier::try_from(3).unwrap(),
        Identifier::try_from(4).unwrap(),
        Identifier::try_from(5).unwrap(),
    ];

    const NEW_MAX_SIGNERS: u16 = 4;

    let (zero_shares, new_pub_key_package) = calculate_zero_key(
        pub_key_package,
        NEW_MAX_SIGNERS,
        min_signers,
        &remaining_ids,
        &mut rng,
    )
    .unwrap();

    // Trusted dealer serialises zero shares and key package

    let zero_shares_serialised = SecretShare::<C>::serialize(&zero_shares[0]);

    assert!(zero_shares_serialised.is_ok());

    let new_pub_key_package_serialised = PublicKeyPackage::<C>::serialize(&new_pub_key_package);

    assert!(new_pub_key_package_serialised.is_ok());

    // Participant 1 deserialises zero share and key package

    let zero_share = SecretShare::<C>::deserialize(&zero_shares_serialised.unwrap());

    assert!(zero_share.is_ok());

    let new_pub_key_package =
        PublicKeyPackage::<C>::deserialize(&new_pub_key_package_serialised.unwrap());

    assert!(new_pub_key_package.is_ok());

    // Participant 1 checks Key Package can be created from Secret Share

    let key_package = KeyPackage::<C>::try_from(zero_share.unwrap());

    assert!(key_package.is_ok());
}
