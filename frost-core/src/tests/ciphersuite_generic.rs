//! Ciphersuite-generic test functions.
use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
};

use crate::{
    frost::{self, Identifier},
    Error, Field, Group, Signature, VerifyingKey,
};
use rand_core::{CryptoRng, RngCore};

use crate::Ciphersuite;

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

    for secret_share in secret_shares.iter() {
        assert!(secret_share.verify().is_ok());
    }

    assert_eq!(
        frost::keys::reconstruct::<C>(&secret_shares)
            .unwrap()
            .serialize()
            .as_ref(),
        secret.serialize().as_ref()
    );

    // Test error cases

    assert_eq!(
        frost::keys::reconstruct::<C>(&[]).unwrap_err(),
        Error::IncorrectNumberOfShares
    );

    let mut secret_shares = secret_shares;
    secret_shares[0] = secret_shares[1].clone();

    assert_eq!(
        frost::keys::reconstruct::<C>(&secret_shares).unwrap_err(),
        Error::DuplicatedShares
    );
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
    let mut key_packages: HashMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> =
        HashMap::new();

    for (k, v) in shares {
        let key_package = frost::keys::KeyPackage::try_from(v).unwrap();
        key_packages.insert(k, key_package);
    }

    check_sign(min_signers, key_packages, rng, pubkeys)
}

fn check_sign<C: Ciphersuite + PartialEq, R: RngCore + CryptoRng>(
    min_signers: u16,
    key_packages: HashMap<frost::Identifier<C>, frost::keys::KeyPackage<C>>,
    mut rng: R,
    pubkey_package: frost::keys::PublicKeyPackage<C>,
) -> (Vec<u8>, Signature<C>, VerifyingKey<C>) {
    let mut nonces_map: HashMap<frost::Identifier<C>, frost::round1::SigningNonces<C>> =
        HashMap::new();
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
                .secret_share(),
            &mut rng,
        );
        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares = HashMap::new();
    let message = "message to sign".as_bytes();
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    for participant_identifier in nonces_map.keys() {
        let key_package = key_packages.get(participant_identifier).unwrap();

        let nonces_to_use = &nonces_map.get(participant_identifier).unwrap();

        // Each participant generates their signature share.
        let signature_share =
            frost::round2::sign(&signing_package, nonces_to_use, key_package).unwrap();
        signature_shares.insert(*participant_identifier, signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    check_aggregate_error(
        signing_package.clone(),
        signature_shares.clone(),
        pubkey_package.clone(),
    );

    // Aggregate (also verifies the signature shares)
    let group_signature =
        frost::aggregate(&signing_package, &signature_shares, &pubkey_package).unwrap();

    // Check that the threshold signature can be verified by the group public
    // key (the verification key).
    let is_signature_valid = pubkey_package
        .group_public
        .verify(message, &group_signature)
        .is_ok();
    assert!(is_signature_valid);

    // Check that the threshold signature can be verified by the group public
    // key (the verification key) from KeyPackage.group_public
    for (participant_identifier, _) in nonces_map.clone() {
        let key_package = key_packages.get(&participant_identifier).unwrap();

        assert!(key_package
            .group_public
            .verify(message, &group_signature)
            .is_ok());
    }

    (
        message.to_owned(),
        group_signature,
        pubkey_package.group_public,
    )
}

fn check_aggregate_error<C: Ciphersuite + PartialEq>(
    signing_package: frost::SigningPackage<C>,
    mut signature_shares: HashMap<frost::Identifier<C>, frost::round2::SignatureShare<C>>,
    pubkey_package: frost::keys::PublicKeyPackage<C>,
) {
    let one = <<C as Ciphersuite>::Group as Group>::Field::one();
    // Corrupt a share
    let id = *signature_shares.keys().next().unwrap();
    signature_shares.get_mut(&id).unwrap().share = signature_shares[&id].share + one;
    let e = frost::aggregate(&signing_package, &signature_shares, &pubkey_package).unwrap_err();
    assert_eq!(e.culprit(), Some(id));
    assert_eq!(e, Error::InvalidSignatureShare { culprit: id });
}

/// Test FROST signing with trusted dealer with a Ciphersuite.
pub fn check_sign_with_dkg<C: Ciphersuite + PartialEq, R: RngCore + CryptoRng>(
    mut rng: R,
) -> (Vec<u8>, Signature<C>, VerifyingKey<C>)
where
    C::Group: std::cmp::PartialEq,
{
    ////////////////////////////////////////////////////////////////////////////
    // Key generation, Round 1
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;

    // Keep track of each participant's round 1 secret package.
    // In practice each participant will keep its copy; no one
    // will have all the participant's packages.
    let mut round1_secret_packages: HashMap<
        frost::Identifier<C>,
        frost::keys::dkg::round1::SecretPackage<C>,
    > = HashMap::new();

    // Keep track of all round 1 packages sent to the given participant.
    // This is used to simulate the broadcast; in practice the packages
    // will be sent through some communication channel.
    let mut received_round1_packages: HashMap<
        frost::Identifier<C>,
        HashMap<frost::Identifier<C>, frost::keys::dkg::round1::Package<C>>,
    > = HashMap::new();

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
        // test this is simulated using a HashMap; in practice this will be
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
                .or_insert_with(HashMap::new)
                .insert(participant_identifier, round1_package.clone());
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Key generation, Round 2
    ////////////////////////////////////////////////////////////////////////////

    // Keep track of each participant's round 2 secret package.
    // In practice each participant will keep its copy; no one
    // will have all the participant's packages.
    let mut round2_secret_packages = HashMap::new();

    // Keep track of all round 2 packages sent to the given participant.
    // This is used to simulate the broadcast; in practice the packages
    // will be sent through some communication channel.
    let mut received_round2_packages = HashMap::new();

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
        // test this is simulated using a HashMap; in practice this will be
        // sent through some communication channel.
        // Note that, in contrast to the previous part, here each other participant
        // gets its own specific package.
        for (receiver_identifier, round2_package) in round2_packages {
            received_round2_packages
                .entry(receiver_identifier)
                .or_insert_with(HashMap::new)
                .insert(participant_identifier, round2_package);
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Key generation, final computation
    ////////////////////////////////////////////////////////////////////////////

    // Keep track of each participant's long-lived key package.
    // In practice each participant will keep its copy; no one
    // will have all the participant's packages.
    let mut key_packages = HashMap::new();

    // Map of the verifying key of each participant.
    // Used by the signing test that follows.
    let mut verifying_keys = HashMap::new();
    // The group public key, used by the signing test that follows.
    let mut group_public = None;
    // For each participant, store the set of verifying keys they have computed.
    // This is used to check if the set is correct (the same) for all participants.
    // In practice, if there is a Coordinator, only they need to store the set.
    // If there is not, then all candidates must store their own sets.
    // The verifying keys are used to verify the signature shares produced
    // for each signature before being aggregated.
    let mut pubkey_packages_by_participant = HashMap::new();

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
        verifying_keys.insert(participant_identifier, key_package.public);
        // Test if all group_public are equal
        if let Some(previous_group_public) = group_public {
            assert_eq!(previous_group_public, key_package.group_public)
        }
        group_public = Some(key_package.group_public);
        key_packages.insert(participant_identifier, key_package);
        pubkey_packages_by_participant
            .insert(participant_identifier, pubkey_package_for_participant);
    }

    // Test if the set of verifying keys is correct for all participants.
    for verifying_keys_for_participant in pubkey_packages_by_participant.values() {
        assert!(verifying_keys_for_participant.signer_pubkeys == verifying_keys);
    }

    let pubkeys = frost::keys::PublicKeyPackage::new(verifying_keys, group_public.unwrap());

    // Proceed with the signing test.
    check_sign(min_signers, key_packages, rng, pubkeys)
}

/// Test FROST signing with trusted dealer with a Ciphersuite, using specified
/// Identifiers.
pub fn check_sign_with_dealer_and_identifiers<C: Ciphersuite, R: RngCore + CryptoRng>(
    mut rng: R,
) -> (Vec<u8>, Signature<C>, VerifyingKey<C>) {
    // Check error case first (repeated identifiers)

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

    let mut key_packages: HashMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> =
        HashMap::new();
    for (k, v) in shares {
        let key_package = frost::keys::KeyPackage::try_from(v).unwrap();
        key_packages.insert(k, key_package);
    }
    check_sign(min_signers, key_packages, rng, pubkeys)
}

fn check_part2_error<C: Ciphersuite>(
    round1_secret_package: frost::keys::dkg::round1::SecretPackage<C>,
    mut round1_packages: HashMap<frost::Identifier<C>, frost::keys::dkg::round1::Package<C>>,
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
