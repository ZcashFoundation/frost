//! Test for Refreshing shares

use rand_core::{CryptoRng, RngCore};

use crate::keys::generate_with_dealer;
use crate::keys::refresh::{
    compute_refreshing_shares, refresh_dkg_part2, refresh_dkg_part_1, refresh_share,
};
use crate::{self as frost};
use crate::{
    keys::{KeyPackage, PublicKeyPackage, SecretShare},
    Ciphersuite, Error, Identifier, Signature, VerifyingKey,
};

use crate::tests::ciphersuite_generic::check_part3_different_participants;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::ciphersuite_generic::check_sign;

/// We want to test that recover share matches the original share
pub fn check_refresh_shares_with_dealer<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    // Compute shares

    ////////////////////////////////////////////////////////////////////////////
    // Old Key generation
    ////////////////////////////////////////////////////////////////////////////

    const MAX_SIGNERS: u16 = 5;
    const MIN_SIGNERS: u16 = 3;
    let (old_shares, pub_key_package) = generate_with_dealer(
        MAX_SIGNERS,
        MIN_SIGNERS,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();

    let mut old_key_packages: BTreeMap<frost::Identifier<C>, KeyPackage<C>> = BTreeMap::new();

    for (k, v) in old_shares {
        let key_package = KeyPackage::try_from(v).unwrap();
        old_key_packages.insert(k, key_package);
    }

    ////////////////////////////////////////////////////////////////////////////
    // New Key generation
    ////////////////////////////////////////////////////////////////////////////

    // Signer 2 will be removed and Signers 1, 3, 4 & 5 will remain

    let remaining_ids = vec![
        Identifier::try_from(1).unwrap(),
        Identifier::try_from(3).unwrap(),
        Identifier::try_from(4).unwrap(),
        Identifier::try_from(5).unwrap(),
    ];

    const NEW_MAX_SIGNERS: u16 = 4;

    // Trusted Dealer generates zero keys and new public key package

    let (zero_shares, new_pub_key_package) = compute_refreshing_shares(
        pub_key_package,
        NEW_MAX_SIGNERS,
        MIN_SIGNERS,
        &remaining_ids,
        &mut rng,
    )
    .unwrap();

    // Each participant refreshes their share

    let mut new_shares = BTreeMap::new();

    for i in 0..remaining_ids.len() {
        let identifier = remaining_ids[i];
        let current_share = &old_key_packages[&identifier];
        let new_share = refresh_share(zero_shares[i].clone(), current_share);
        new_shares.insert(identifier, new_share);
    }

    let mut key_packages: BTreeMap<frost::Identifier<C>, KeyPackage<C>> = BTreeMap::new();

    for (k, v) in new_shares {
        key_packages.insert(k, v.unwrap());
    }
    check_sign(MIN_SIGNERS, key_packages, rng, new_pub_key_package).unwrap();
}

/// We want to check that shares are refreshed with valid signers
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
    let (_old_shares, pub_key_package) =
        generate_with_dealer::<C, R>(5, 2, frost::keys::IdentifierList::Default, &mut rng).unwrap();
    let out = compute_refreshing_shares(
        pub_key_package,
        new_max_signers,
        min_signers,
        identifiers,
        &mut rng,
    );

    assert!(out.is_err());
    assert!(out == Err(error))
}

/// We want to test that refresh share fails if the identifiers don't match the
/// identifiers in the public key package
pub fn check_refresh_shares_with_dealer_fails_with_invalid_public_key_package<
    C: Ciphersuite,
    R: RngCore + CryptoRng,
>(
    mut rng: R,
) {
    // Compute shares

    ////////////////////////////////////////////////////////////////////////////
    // Old Key generation
    ////////////////////////////////////////////////////////////////////////////

    const MAX_SIGNERS: u16 = 3;
    const MIN_SIGNERS: u16 = 2;
    let (old_shares, incorrect_pub_key_package) = generate_with_dealer(
        MAX_SIGNERS,
        MIN_SIGNERS,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();

    let mut old_key_packages: BTreeMap<frost::Identifier<C>, KeyPackage<C>> = BTreeMap::new();

    for (k, v) in old_shares {
        let key_package = KeyPackage::try_from(v).unwrap();
        old_key_packages.insert(k, key_package);
    }

    ////////////////////////////////////////////////////////////////////////////
    // New Key generation
    ////////////////////////////////////////////////////////////////////////////

    // Signer 2 will be removed and Signers 1, 3, 4 & 5 will remain

    let remaining_ids = vec![
        Identifier::try_from(1).unwrap(),
        Identifier::try_from(3).unwrap(),
        Identifier::try_from(4).unwrap(),
        Identifier::try_from(5).unwrap(),
    ];

    const NEW_MAX_SIGNERS: u16 = 4;

    // Trusted Dealer generates zero keys and new public key package

    let e = compute_refreshing_shares(
        incorrect_pub_key_package,
        NEW_MAX_SIGNERS,
        MIN_SIGNERS,
        &remaining_ids,
        &mut rng,
    )
    .unwrap_err();

    assert_eq!(e, Error::UnknownIdentifier)
}

/// Check serialisation
pub fn check_refresh_shares_with_dealer_serialisation<C: Ciphersuite, R: RngCore + CryptoRng>(
    mut rng: R,
) {
    ////////////////////////////////////////////////////////////////////////////
    // Old Key generation
    ////////////////////////////////////////////////////////////////////////////

    const MAX_SIGNERS: u16 = 5;
    const MIN_SIGNERS: u16 = 3;
    let (_old_shares, pub_key_package) = generate_with_dealer(
        MAX_SIGNERS,
        MIN_SIGNERS,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();

    ////////////////////////////////////////////////////////////////////////////
    // New Key generation
    //
    // Zero key is calculated by trusted dealer
    // Participant 2 will be removed and Participants 1, 3, 4 & 5 will remain
    ////////////////////////////////////////////////////////////////////////////

    let remaining_ids = vec![
        Identifier::try_from(1).unwrap(),
        Identifier::try_from(3).unwrap(),
        Identifier::try_from(4).unwrap(),
        Identifier::try_from(5).unwrap(),
    ];

    const NEW_MAX_SIGNERS: u16 = 4;

    let (zero_shares, new_pub_key_package) = compute_refreshing_shares(
        pub_key_package,
        NEW_MAX_SIGNERS,
        MIN_SIGNERS,
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

/// Test FROST signing with DKG with a Ciphersuite.
pub fn check_refresh_shares_with_dkg<C: Ciphersuite + PartialEq, R: RngCore + CryptoRng>(
    mut rng: R,
) -> (Vec<u8>, Signature<C>, VerifyingKey<C>)
where
    C::Group: core::cmp::PartialEq,
{
    ////////////////////////////////////////////////////////////////////////////
    // Old Key generation
    ////////////////////////////////////////////////////////////////////////////

    let old_max_signers = 5;
    let min_signers = 3;
    let (old_shares, pub_key_package) = generate_with_dealer(
        old_max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();

    let mut old_key_packages: BTreeMap<frost::Identifier<C>, KeyPackage<C>> = BTreeMap::new();

    for (k, v) in old_shares {
        let key_package = KeyPackage::try_from(v).unwrap();
        old_key_packages.insert(k, key_package);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Key generation, Round 1
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 4;
    let min_signers = 3;

    let remaining_ids = vec![
        Identifier::try_from(4).unwrap(),
        Identifier::try_from(2).unwrap(),
        Identifier::try_from(3).unwrap(),
        Identifier::try_from(1).unwrap(),
    ];

    // Keep track of each participant's round 1 secret package.
    // In practice each participant will keep its copy; no one
    // will have all the participant's packages.
    let mut round1_secret_packages: BTreeMap<
        frost::Identifier<C>,
        frost::keys::dkg::round1::SecretPackage<C>,
    > = BTreeMap::new();

    // Keep track of all round 1 packages sent to the given participant.
    // This is used to simulate the broadcast; in practice the packages
    // will be sent through some communication channel.
    let mut received_round1_packages: BTreeMap<
        frost::Identifier<C>,
        BTreeMap<frost::Identifier<C>, frost::keys::dkg::round1::Package<C>>,
    > = BTreeMap::new();

    // For each participant, perform the first part of the DKG protocol.
    // In practice, each participant will perform this on their own environments.
    for participant_identifier in remaining_ids.clone() {
        let (round1_secret_package, round1_package) =
            refresh_dkg_part_1(participant_identifier, max_signers, min_signers, &mut rng).unwrap();

        // Store the participant's secret package for later use.
        // In practice each participant will store it in their own environment.
        round1_secret_packages.insert(participant_identifier, round1_secret_package);

        // "Send" the round 1 package to all other participants. In this
        // test this is simulated using a BTreeMap; in practice this will be
        // sent through some communication channel.
        for receiver_participant_identifier in remaining_ids.clone() {
            if receiver_participant_identifier == participant_identifier {
                continue;
            }
            received_round1_packages
                .entry(receiver_participant_identifier)
                .or_default()
                .insert(participant_identifier, round1_package.clone());
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Key generation, Round 2
    ////////////////////////////////////////////////////////////////////////////
    // Keep track of each participant's round 2 secret package.
    // In practice each participant will keep its copy; no one
    // will have all the participant's packages.
    let mut round2_secret_packages = BTreeMap::new();

    // Keep track of all round 2 packages sent to the given participant.
    // This is used to simulate the broadcast; in practice the packages
    // will be sent through some communication channel.
    let mut received_round2_packages = BTreeMap::new();

    // For each participant, perform the second part of the DKG protocol.
    // In practice, each participant will perform this on their own environments.
    for participant_identifier in remaining_ids.clone() {
        let round1_secret_package = round1_secret_packages
            .remove(&participant_identifier)
            .unwrap();
        let round1_packages = &received_round1_packages[&participant_identifier];
        let (round2_secret_package, round2_packages) =
            refresh_dkg_part2(round1_secret_package, round1_packages).expect("should work");

        // Store the participant's secret package for later use.
        // In practice each participant will store it in their own environment.
        round2_secret_packages.insert(participant_identifier, round2_secret_package);

        // "Send" the round 2 package to all other participants. In this
        // test this is simulated using a BTreeMap; in practice this will be
        // sent through some communication channel.
        // Note that, in contrast to the previous part, here each other participant
        // gets its own specific package.
        for (receiver_identifier, round2_package) in round2_packages {
            received_round2_packages
                .entry(receiver_identifier)
                .or_insert_with(BTreeMap::new)
                .insert(participant_identifier, round2_package);
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Key generation, final computation
    ////////////////////////////////////////////////////////////////////////////

    // Keep track of each participant's long-lived key package.
    // In practice each participant will keep its copy; no one
    // will have all the participant's packages.
    let mut key_packages = BTreeMap::new();

    // Map of the verifying key of each participant.
    // Used by the signing test that follows.
    let mut verifying_keys = BTreeMap::new();
    // The group public key, used by the signing test that follows.
    let mut verifying_key = None;
    // For each participant, store the set of verifying keys they have computed.
    // This is used to check if the set is correct (the same) for all participants.
    // In practice, if there is a Coordinator, only they need to store the set.
    // If there is not, then all candidates must store their own sets.
    // The verifying keys are used to verify the signature shares produced
    // for each signature before being aggregated.
    let mut pubkey_packages_by_participant = BTreeMap::new();

    check_part3_different_participants(
        max_signers,
        round2_secret_packages.clone(),
        received_round1_packages.clone(),
        received_round2_packages.clone(),
    );

    // For each participant, this is where they refresh their shares
    // In practice, each participant will perform this on their own environments.
    for participant_identifier in remaining_ids.clone() {
        let (key_package, pubkey_package_for_participant) =
            frost::keys::refresh::refresh_dkg_shares(
                &round2_secret_packages[&participant_identifier],
                &received_round1_packages[&participant_identifier],
                &received_round2_packages[&participant_identifier],
                pub_key_package.clone(),
                old_key_packages[&participant_identifier].clone(),
            )
            .unwrap();
        verifying_keys.insert(participant_identifier, key_package.verifying_share);
        // Test if all verifying_key are equal
        if let Some(previous_verifying_key) = verifying_key {
            assert_eq!(previous_verifying_key, key_package.verifying_key)
        }
        verifying_key = Some(key_package.verifying_key);
        key_packages.insert(participant_identifier, key_package);
        pubkey_packages_by_participant
            .insert(participant_identifier, pubkey_package_for_participant);
    }

    // Test if the set of verifying keys is correct for all participants.
    for verifying_keys_for_participant in pubkey_packages_by_participant.values() {
        assert!(verifying_keys_for_participant.verifying_shares == verifying_keys);
    }

    let pubkeys = frost::keys::PublicKeyPackage::new(verifying_keys, verifying_key.unwrap());

    // Proceed with the signing test.
    check_sign(min_signers, key_packages, rng, pubkeys).unwrap()
}
