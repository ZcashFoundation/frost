//! Ciphersuite-generic test functions.
#![allow(clippy::type_complexity)]

use alloc::collections::BTreeMap;

use crate as frost;
use crate::round2::SignatureShare;
use crate::{
    keys::PublicKeyPackage, Error, Field, Group, Identifier, Signature, SigningKey, SigningPackage,
    VerifyingKey,
};
use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

use crate::Ciphersuite;

/// Test if creating a zero SigningKey fails
pub fn check_zero_key_fails<C: Ciphersuite>() {
    let zero = <<<C as Ciphersuite>::Group as Group>::Field>::zero();
    let encoded_zero = <<<C as Ciphersuite>::Group as Group>::Field>::serialize(&zero);
    let r = SigningKey::<C>::deserialize(encoded_zero.as_ref());
    assert_eq!(r, Err(Error::MalformedSigningKey));
}

/// Test share generation with a Ciphersuite
pub fn check_share_generation<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    let secret = crate::SigningKey::<C>::new(&mut rng);

    let max_signers = 5;
    let min_signers = 3;

    let coefficients =
        frost::keys::generate_coefficients::<C, _>(min_signers as usize - 1, &mut rng);

    let secret_shares = frost::keys::generate_secret_shares(
        &secret,
        max_signers,
        min_signers,
        coefficients,
        &frost::keys::default_identifiers(max_signers),
    )
    .unwrap();

    let key_packages: Vec<frost::keys::KeyPackage<C>> = secret_shares
        .iter()
        .cloned()
        .map(|s| s.try_into().unwrap())
        .collect();

    assert_eq!(
        frost::keys::reconstruct::<C>(&key_packages)
            .unwrap()
            .serialize(),
        secret.serialize()
    );

    // Test error cases

    assert_eq!(
        frost::keys::reconstruct::<C>(&[]).unwrap_err(),
        Error::IncorrectNumberOfShares
    );

    assert_eq!(
        frost::keys::reconstruct::<C>(&key_packages[0..1]).unwrap_err(),
        Error::IncorrectNumberOfShares
    );

    let mut key_packages = key_packages;
    key_packages[0] = key_packages[1].clone();

    assert_eq!(
        frost::keys::reconstruct::<C>(&key_packages).unwrap_err(),
        Error::DuplicatedIdentifier
    );
}

/// Test share generation with a Ciphersuite
pub fn check_share_generation_fails_with_invalid_signers<C: Ciphersuite, R: RngCore + CryptoRng>(
    min_signers: u16,
    max_signers: u16,
    error: Error<C>,
    mut rng: R,
) {
    let secret = crate::SigningKey::<C>::new(&mut rng);

    // Use arbitrary number of coefficients so tests don't fail for overflow reasons
    let coefficients = frost::keys::generate_coefficients::<C, _>(3, &mut rng);

    let secret_shares = frost::keys::generate_secret_shares(
        &secret,
        max_signers,
        min_signers,
        coefficients,
        &frost::keys::default_identifiers(max_signers),
    );

    assert!(secret_shares.is_err());
    assert!(secret_shares == Err(error))
}

/// Test FROST signing with trusted dealer with a Ciphersuite.
pub fn check_sign_with_dealer<C: Ciphersuite, R: RngCore + CryptoRng>(
    mut rng: R,
) -> (Vec<u8>, Signature<C>, VerifyingKey<C>) {
    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;
    let (shares, pubkeys) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();

    // Verifies the secret shares from the dealer
    let mut key_packages: BTreeMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> =
        BTreeMap::new();

    for (k, v) in shares {
        let key_package = frost::keys::KeyPackage::try_from(v).unwrap();
        key_packages.insert(k, key_package);
    }
    // Check if it fails with not enough signers. Usually this would return an
    // error before even running the signing procedure, because `KeyPackage`
    // contains the correct `min_signers` value and the signing procedure checks
    // if the number of shares is at least `min_signers`. To bypass the check
    // and test if the protocol itself fails with not enough signers, we modify
    // the `KeyPackages`s, decrementing their saved `min_signers` value before
    // running the signing procedure.
    let r = check_sign(
        min_signers - 1,
        key_packages
            .iter()
            .map(|(id, k)| {
                // Decrement `min_signers` as explained above and use
                // the updated `KeyPackage`.
                let mut k = k.clone();
                k.min_signers -= 1;
                (*id, k)
            })
            .collect(),
        &mut rng,
        pubkeys.clone(),
    );
    assert_eq!(r, Err(Error::InvalidSignature));

    check_sign(min_signers, key_packages, rng, pubkeys).unwrap()
}

/// Test FROST signing with trusted dealer fails with invalid numbers of signers.
pub fn check_sign_with_dealer_fails_with_invalid_signers<C: Ciphersuite, R: RngCore + CryptoRng>(
    min_signers: u16,
    max_signers: u16,
    error: Error<C>,
    mut rng: R,
) {
    let out = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default::<C>,
        &mut rng,
    );

    assert!(out.is_err());
    assert!(out == Err(error))
}

/// Test DKG part1 fails with invalid numbers of signers.
pub fn check_dkg_part1_fails_with_invalid_signers<C: Ciphersuite, R: RngCore + CryptoRng>(
    min_signers: u16,
    max_signers: u16,
    error: Error<C>,
    mut rng: R,
) {
    let out = frost::keys::dkg::part1(
        Identifier::try_from(1).unwrap(),
        max_signers,
        min_signers,
        &mut rng,
    );

    assert!(out.is_err());
    assert!(out == Err(error))
}

/// Test FROST signing with the given shares.
pub fn check_sign<C: Ciphersuite + PartialEq, R: RngCore + CryptoRng>(
    min_signers: u16,
    key_packages: BTreeMap<frost::Identifier<C>, frost::keys::KeyPackage<C>>,
    mut rng: R,
    pubkey_package: PublicKeyPackage<C>,
) -> Result<(Vec<u8>, Signature<C>, VerifyingKey<C>), Error<C>> {
    let mut nonces_map: BTreeMap<frost::Identifier<C>, frost::round1::SigningNonces<C>> =
        BTreeMap::new();
    let mut commitments_map: BTreeMap<frost::Identifier<C>, frost::round1::SigningCommitments<C>> =
        BTreeMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    for participant_identifier in key_packages.keys().take(min_signers as usize).cloned() {
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _min_signers_.
        let (nonces, commitments) = frost::round1::commit(
            key_packages
                .get(&participant_identifier)
                .unwrap()
                .signing_share(),
            &mut rng,
        );
        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares = BTreeMap::new();
    let message = "message to sign".as_bytes();
    let signing_package = SigningPackage::new(commitments_map, message);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    for participant_identifier in nonces_map.keys() {
        let key_package = key_packages.get(participant_identifier).unwrap();

        let nonces_to_use = nonces_map.get(participant_identifier).unwrap();

        check_sign_errors(
            signing_package.clone(),
            nonces_to_use.clone(),
            key_package.clone(),
        );

        // Each participant generates their signature share.
        let signature_share = frost::round2::sign(&signing_package, nonces_to_use, key_package)?;
        signature_shares.insert(*participant_identifier, signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    check_aggregate_errors(
        signing_package.clone(),
        signature_shares.clone(),
        pubkey_package.clone(),
    );

    check_verifying_shares(
        pubkey_package.clone(),
        signing_package.clone(),
        signature_shares.clone(),
    );

    // Aggregate (also verifies the signature shares)
    let group_signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;

    // Check that the threshold signature can be verified by the group public
    // key (the verification key).
    pubkey_package
        .verifying_key
        .verify(message, &group_signature)?;

    // Check that the threshold signature can be verified by the group public
    // key (the verification key) from KeyPackage.verifying_key
    for (participant_identifier, _) in nonces_map.clone() {
        let key_package = key_packages.get(&participant_identifier).unwrap();

        key_package
            .verifying_key
            .verify(message, &group_signature)?;
    }

    Ok((
        message.to_owned(),
        group_signature,
        pubkey_package.verifying_key,
    ))
}

fn check_sign_errors<C: Ciphersuite + PartialEq>(
    signing_package: frost::SigningPackage<C>,
    signing_nonces: frost::round1::SigningNonces<C>,
    key_package: frost::keys::KeyPackage<C>,
) {
    // Check if passing not enough commitments causes an error

    let mut commitments = signing_package.signing_commitments().clone();
    // Remove one commitment that's not from the key_package owner
    let id = *commitments
        .keys()
        .find(|&&id| id != key_package.identifier)
        .unwrap();
    commitments.remove(&id);
    let signing_package = frost::SigningPackage::new(commitments, signing_package.message());

    let r = frost::round2::sign(&signing_package, &signing_nonces, &key_package);
    assert_eq!(r, Err(Error::IncorrectNumberOfCommitments));
}

fn check_aggregate_errors<C: Ciphersuite + PartialEq>(
    signing_package: frost::SigningPackage<C>,
    signature_shares: BTreeMap<frost::Identifier<C>, frost::round2::SignatureShare<C>>,
    pubkey_package: frost::keys::PublicKeyPackage<C>,
) {
    #[cfg(not(feature = "cheater-detection"))]
    let pubkey_package = PublicKeyPackage {
        header: pubkey_package.header,
        verifying_shares: BTreeMap::new(),
        verifying_key: pubkey_package.verifying_key,
    };

    #[cfg(feature = "cheater-detection")]
    check_aggregate_corrupted_share(
        signing_package.clone(),
        signature_shares.clone(),
        pubkey_package.clone(),
    );

    check_aggregate_invalid_share_identifier_for_verifying_shares(
        signing_package,
        signature_shares,
        pubkey_package,
    );
}

#[cfg(feature = "cheater-detection")]
fn check_aggregate_corrupted_share<C: Ciphersuite + PartialEq>(
    signing_package: frost::SigningPackage<C>,
    mut signature_shares: BTreeMap<frost::Identifier<C>, frost::round2::SignatureShare<C>>,
    pubkey_package: frost::keys::PublicKeyPackage<C>,
) {
    use crate::round2::SignatureShare;

    let one = <<C as Ciphersuite>::Group as Group>::Field::one();
    // Corrupt a share
    let id = *signature_shares.keys().next().unwrap();
    *signature_shares.get_mut(&id).unwrap() =
        SignatureShare::new(signature_shares[&id].to_scalar() + one);
    let e = frost::aggregate(&signing_package, &signature_shares, &pubkey_package).unwrap_err();
    assert_eq!(e.culprit(), Some(id));
    assert_eq!(e, Error::InvalidSignatureShare { culprit: id });
}

/// Test NCC-E008263-4VP audit finding (PublicKeyPackage).
/// Note that the SigningPackage part of the finding is not currently reachable
/// since it's caught by `compute_lagrange_coefficient()`, and the Binding Factor
/// part can't either since it's caught before by the PublicKeyPackage part.
fn check_aggregate_invalid_share_identifier_for_verifying_shares<C: Ciphersuite + PartialEq>(
    signing_package: frost::SigningPackage<C>,
    mut signature_shares: BTreeMap<frost::Identifier<C>, frost::round2::SignatureShare<C>>,
    pubkey_package: frost::keys::PublicKeyPackage<C>,
) {
    let invalid_identifier = Identifier::derive("invalid identifier".as_bytes()).unwrap();
    // Insert a new share (copied from other existing share) with an invalid identifier
    signature_shares.insert(
        invalid_identifier,
        *signature_shares.values().next().unwrap(),
    );
    // Should error, but not panic
    frost::aggregate(&signing_package, &signature_shares, &pubkey_package)
        .expect_err("should not work");
}

/// Test FROST signing with DKG with a Ciphersuite.
pub fn check_sign_with_dkg<C: Ciphersuite + PartialEq, R: RngCore + CryptoRng>(
    mut rng: R,
) -> (Vec<u8>, Signature<C>, VerifyingKey<C>)
where
    C::Group: core::cmp::PartialEq,
{
    ////////////////////////////////////////////////////////////////////////////
    // Key generation, Round 1
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;

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
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let (round1_secret_package, round1_package) =
            frost::keys::dkg::part1(participant_identifier, max_signers, min_signers, &mut rng)
                .unwrap();

        // Store the participant's secret package for later use.
        // In practice each participant will store it in their own environment.
        round1_secret_packages.insert(participant_identifier, round1_secret_package);

        // "Send" the round 1 package to all other participants. In this
        // test this is simulated using a BTreeMap; in practice this will be
        // sent through some communication channel.
        for receiver_participant_index in 1..=max_signers {
            if receiver_participant_index == participant_index {
                continue;
            }
            let receiver_participant_identifier = receiver_participant_index
                .try_into()
                .expect("should be nonzero");
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
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let round1_secret_package = round1_secret_packages
            .remove(&participant_identifier)
            .unwrap();
        let round1_packages = &received_round1_packages[&participant_identifier];
        check_part2_error(round1_secret_package.clone(), round1_packages.clone());
        let (round2_secret_package, round2_packages) =
            frost::keys::dkg::part2(round1_secret_package, round1_packages).expect("should work");

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

    // For each participant, perform the third part of the DKG protocol.
    // In practice, each participant will perform this on their own environments.
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let (key_package, pubkey_package_for_participant) = frost::keys::dkg::part3(
            &round2_secret_packages[&participant_identifier],
            &received_round1_packages[&participant_identifier],
            &received_round2_packages[&participant_identifier],
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

/// Check that calling dkg::part3() with distinct sets of participants fail.
fn check_part3_different_participants<C: Ciphersuite>(
    max_signers: u16,
    round2_secret_packages: BTreeMap<Identifier<C>, frost::keys::dkg::round2::SecretPackage<C>>,
    received_round1_packages: BTreeMap<
        Identifier<C>,
        BTreeMap<Identifier<C>, frost::keys::dkg::round1::Package<C>>,
    >,
    received_round2_packages: BTreeMap<
        Identifier<C>,
        BTreeMap<Identifier<C>, frost::keys::dkg::round2::Package<C>>,
    >,
) {
    // For each participant, perform the third part of the DKG protocol.
    // In practice, each participant will perform this on their own environments.
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");

        // Remove the first package from the map, and reinsert it with an unrelated
        // Do the same for Round 2 packages
        let mut received_round2_packages =
            received_round2_packages[&participant_identifier].clone();
        let package = received_round2_packages
            .remove(&received_round2_packages.keys().next().unwrap().clone())
            .unwrap();
        received_round2_packages.insert(42u16.try_into().unwrap(), package);

        let r = frost::keys::dkg::part3(
            &round2_secret_packages[&participant_identifier],
            &received_round1_packages[&participant_identifier],
            &received_round2_packages,
        )
        .expect_err("Should have failed due to different identifier sets");
        assert_eq!(r, Error::IncorrectPackage)
    }
}

/// Test FROST signing with trusted dealer with a Ciphersuite, using specified
/// Identifiers.
pub fn check_sign_with_dealer_and_identifiers<C: Ciphersuite, R: RngCore + CryptoRng>(
    mut rng: R,
) -> (Vec<u8>, Signature<C>, VerifyingKey<C>) {
    // Check error cases first
    // Check repeated identifiers

    let identifiers: Vec<frost::Identifier<C>> = [1u16, 42, 100, 257, 42]
        .into_iter()
        .map(|i| i.try_into().unwrap())
        .collect();
    let max_signers = 5;
    let min_signers = 3;
    let err = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Custom(&identifiers),
        &mut rng,
    )
    .unwrap_err();
    assert_eq!(err, Error::DuplicatedIdentifier);

    // Check incorrect number of identifiers

    let identifiers: Vec<frost::Identifier<C>> = [1u16, 42, 100, 257]
        .into_iter()
        .map(|i| i.try_into().unwrap())
        .collect();
    let max_signers = 5;
    let min_signers = 3;
    let err = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Custom(&identifiers),
        &mut rng,
    )
    .unwrap_err();
    assert_eq!(err, Error::IncorrectNumberOfIdentifiers);

    // Check correct case

    let identifiers: Vec<frost::Identifier<C>> = [1u16, 42, 100, 257, 65535]
        .into_iter()
        .map(|i| i.try_into().unwrap())
        .collect();

    let max_signers = 5;
    let min_signers = 3;
    let (shares, pubkeys) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Custom(&identifiers),
        &mut rng,
    )
    .unwrap();

    // Check if the specified identifiers were used
    for id in identifiers {
        assert!(shares.contains_key(&id));
    }

    // Do regular testing to make sure it works

    let mut key_packages: BTreeMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> =
        BTreeMap::new();
    for (k, v) in shares {
        let key_package = frost::keys::KeyPackage::try_from(v).unwrap();
        key_packages.insert(k, key_package);
    }
    check_sign(min_signers, key_packages, rng, pubkeys).unwrap()
}

fn check_part2_error<C: Ciphersuite>(
    round1_secret_package: frost::keys::dkg::round1::SecretPackage<C>,
    mut round1_packages: BTreeMap<frost::Identifier<C>, frost::keys::dkg::round1::Package<C>>,
) {
    let one = <<C as Ciphersuite>::Group as Group>::Field::one();
    // Corrupt a PoK
    let id = *round1_packages.keys().next().unwrap();
    round1_packages.get_mut(&id).unwrap().proof_of_knowledge.z =
        round1_packages[&id].proof_of_knowledge.z + one;
    let e = frost::keys::dkg::part2(round1_secret_package, &round1_packages).unwrap_err();
    assert_eq!(e.culprit(), Some(id));
    assert_eq!(e, Error::InvalidProofOfKnowledge { culprit: id });
}

/// Test Error culprit method.
pub fn check_error_culprit<C: Ciphersuite>() {
    let identifier: frost::Identifier<C> = 42u16.try_into().unwrap();

    let e = Error::InvalidSignatureShare {
        culprit: identifier,
    };
    assert_eq!(e.culprit(), Some(identifier));

    let e = Error::InvalidProofOfKnowledge {
        culprit: identifier,
    };
    assert_eq!(e.culprit(), Some(identifier));

    let e: Error<C> = Error::InvalidSignature;
    assert_eq!(e.culprit(), None);
}

/// Test identifier derivation with a Ciphersuite
pub fn check_identifier_derivation<C: Ciphersuite>() {
    let id1a = Identifier::<C>::derive("username1".as_bytes()).unwrap();
    let id1b = Identifier::<C>::derive("username1".as_bytes()).unwrap();
    let id2 = Identifier::<C>::derive("username2".as_bytes()).unwrap();

    assert!(id1a == id1b);
    assert!(id1a != id2);
}

/// Checks the signer's identifier is included in the package
pub fn check_sign_with_missing_identifier<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;
    let (shares, _pubkeys) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();

    // Verifies the secret shares from the dealer
    let mut key_packages: BTreeMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> =
        BTreeMap::new();

    for (k, v) in shares {
        let key_package = frost::keys::KeyPackage::try_from(v).unwrap();
        key_packages.insert(k, key_package);
    }

    let mut nonces_map: BTreeMap<frost::Identifier<C>, frost::round1::SigningNonces<C>> =
        BTreeMap::new();
    let mut commitments_map: BTreeMap<frost::Identifier<C>, frost::round1::SigningCommitments<C>> =
        BTreeMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    let id_1 = Identifier::<C>::try_from(1).unwrap();
    let id_2 = Identifier::<C>::try_from(2).unwrap();
    let id_3 = Identifier::<C>::try_from(3).unwrap();
    let id_4 = Identifier::<C>::try_from(4).unwrap();
    let key_packages_inc = vec![id_1, id_2, id_3];

    for participant_identifier in key_packages_inc {
        // The nonces and commitments for each participant are generated.
        let (nonces, commitments) = frost::round1::commit(
            key_packages
                .get(&participant_identifier)
                .unwrap()
                .signing_share(),
            &mut rng,
        );
        nonces_map.insert(participant_identifier, nonces);

        // Participant with id_1 is excluded from the commitments_map so it is missing from the signing package.
        // To prevent sign() from returning an error due to incorrect number of commitments,
        // add the commitment under another unrelated participant.
        if participant_identifier == id_1 {
            commitments_map.insert(id_4, commitments);
        } else {
            commitments_map.insert(participant_identifier, commitments);
        }
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let message = "message to sign".as_bytes();
    let signing_package = SigningPackage::new(commitments_map, message);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: Participant with id_1 signs
    ////////////////////////////////////////////////////////////////////////////

    let key_package_1 = key_packages.get(&id_1).unwrap();

    let nonces_to_use = &nonces_map.get(&id_1).unwrap();

    // Each participant generates their signature share.
    let signature_share = frost::round2::sign(&signing_package, nonces_to_use, key_package_1);

    assert_eq!(signature_share, Err(Error::MissingCommitment))
}

/// Checks the signer's commitment is valid
pub fn check_sign_with_incorrect_commitments<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;
    let (shares, _pubkeys) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();

    // Verifies the secret shares from the dealer
    let mut key_packages: BTreeMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> =
        BTreeMap::new();

    for (k, v) in shares {
        let key_package = frost::keys::KeyPackage::try_from(v).unwrap();
        key_packages.insert(k, key_package);
    }

    let mut commitments_map: BTreeMap<frost::Identifier<C>, frost::round1::SigningCommitments<C>> =
        BTreeMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    let id_1 = Identifier::<C>::try_from(1).unwrap();
    let id_2 = Identifier::<C>::try_from(2).unwrap();
    let id_3 = Identifier::<C>::try_from(3).unwrap();
    // let key_packages_inc = vec![id_1, id_2, id_3];

    let (_nonces_1, commitments_1) =
        frost::round1::commit(key_packages[&id_1].signing_share(), &mut rng);

    let (_nonces_2, commitments_2) =
        frost::round1::commit(key_packages[&id_2].signing_share(), &mut rng);

    let (nonces_3, _commitments_3) =
        frost::round1::commit(key_packages[&id_3].signing_share(), &mut rng);

    commitments_map.insert(id_1, commitments_1);
    commitments_map.insert(id_2, commitments_2);
    // Invalid commitment for id_3
    commitments_map.insert(id_3, commitments_1);

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let message = "message to sign".as_bytes();
    let signing_package = SigningPackage::new(commitments_map, message);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: Participant with id_3 signs
    ////////////////////////////////////////////////////////////////////////////

    let key_package_3 = key_packages.get(&id_3).unwrap();

    // Each participant generates their signature share.
    let signature_share = frost::round2::sign(&signing_package, &nonces_3, key_package_3);

    assert!(signature_share.is_err());
    assert!(signature_share == Err(Error::IncorrectCommitment))
}

// Checks the verifying shares are valid
//
// NOTE: If the last verifying share is invalid this test will not detect this.
// The test is intended for ensuring the correct calculation of verifying shares
// which is covered in this test
fn check_verifying_shares<C: Ciphersuite>(
    pubkeys: PublicKeyPackage<C>,
    signing_package: SigningPackage<C>,
    mut signature_shares: BTreeMap<Identifier<C>, SignatureShare<C>>,
) {
    let one = <<C as Ciphersuite>::Group as Group>::Field::one();

    // Corrupt last share
    let id = *signature_shares.keys().last().unwrap();
    *signature_shares.get_mut(&id).unwrap() =
        SignatureShare::new(signature_shares[&id].to_scalar() + one);

    let e = frost::aggregate(&signing_package, &signature_shares, &pubkeys).unwrap_err();
    assert_eq!(e.culprit(), Some(id));
    assert_eq!(e, Error::InvalidSignatureShare { culprit: id });
}
