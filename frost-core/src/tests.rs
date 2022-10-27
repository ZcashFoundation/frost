//! Ciphersuite-generic test functions.
use std::{collections::HashMap, convert::TryFrom};

use crate::frost;
use rand_core::{CryptoRng, RngCore};

use crate::Ciphersuite;

pub mod batch;
pub mod proptests;
pub mod vectors;

/// Test share generation with a Ciphersuite
pub fn check_share_generation<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    let secret = frost::keys::SharedSecret::<C>::random(&mut rng);

    let max_signers = 5;
    let min_signers = 3;

    let coefficients =
        frost::keys::generate_coefficients::<C, _>(min_signers as usize - 1, &mut rng);

    let secret_shares =
        frost::keys::generate_secret_shares(&secret, max_signers, min_signers, coefficients)
            .unwrap();

    for secret_share in secret_shares.iter() {
        assert!(secret_share.verify().is_ok());
    }

    assert_eq!(
        frost::keys::reconstruct_secret::<C>(secret_shares).unwrap(),
        secret
    )
}

/// Test FROST signing with trusted dealer with a Ciphersuite.
pub fn check_sign_with_dealer<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;
    let (shares, pubkeys) =
        frost::keys::keygen_with_dealer(max_signers, min_signers, &mut rng).unwrap();

    // Verifies the secret shares from the dealer
    let key_packages: HashMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> = shares
        .into_iter()
        .map(|share| {
            (
                share.identifier,
                frost::keys::KeyPackage::try_from(share).unwrap(),
            )
        })
        .collect();

    check_sign(min_signers, key_packages, rng, pubkeys);
}

fn check_sign<C: Ciphersuite + PartialEq, R: RngCore + CryptoRng>(
    min_signers: u16,
    key_packages: HashMap<frost::Identifier<C>, frost::keys::KeyPackage<C>>,
    mut rng: R,
    pubkeys: frost::keys::PublicKeyPackage<C>,
) {
    let mut nonces: HashMap<frost::Identifier<C>, frost::round1::SigningNonces<C>> = HashMap::new();
    let mut commitments: HashMap<frost::Identifier<C>, frost::round1::SigningCommitments<C>> =
        HashMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    for participant_index in 1..(min_signers as u16 + 1) {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _min_signers_.
        let (nonce, commitment) = frost::round1::commit(
            participant_identifier,
            key_packages
                .get(&participant_identifier)
                .unwrap()
                .secret_share(),
            &mut rng,
        );
        nonces.insert(participant_identifier, nonce);
        commitments.insert(participant_identifier, commitment);
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares: Vec<frost::round2::SignatureShare<C>> = Vec::new();
    let message = "message to sign".as_bytes();
    let comms = commitments.clone().into_values().collect();
    let signing_package = frost::SigningPackage::new(comms, message.to_vec());

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    for participant_identifier in nonces.keys() {
        let key_package = key_packages.get(participant_identifier).unwrap();

        let nonces_to_use = &nonces.get(participant_identifier).unwrap();

        // Each participant generates their signature share.
        let signature_share =
            frost::round2::sign(&signing_package, nonces_to_use, key_package).unwrap();
        signature_shares.push(signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate (also verifies the signature shares)
    let group_signature_res = frost::aggregate(&signing_package, &signature_shares[..], &pubkeys);

    assert!(group_signature_res.is_ok());

    let group_signature = group_signature_res.unwrap();

    // Check that the threshold signature can be verified by the group public
    // key (the verification key).
    assert!(pubkeys
        .group_public
        .verify(message, &group_signature)
        .is_ok());

    // Check that the threshold signature can be verified by the group public
    // key (the verification key) from KeyPackage.group_public
    for (participant_identifier, _) in nonces.clone() {
        let key_package = key_packages.get(&participant_identifier).unwrap();

        assert!(key_package
            .group_public
            .verify(message, &group_signature)
            .is_ok());
    }
}

/// Test FROST signing with trusted dealer with a Ciphersuite.
pub fn check_sign_with_dkg<C: Ciphersuite + PartialEq, R: RngCore + CryptoRng>(mut rng: R)
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
        frost::keys::dkg::Round1SecretPackage<C>,
    > = HashMap::new();

    // Keep track of all round 1 packages sent to the given participant.
    // This is used to simulate the broadcast; in practice the packages
    // will be sent through some communication channel.
    let mut received_round1_packages: HashMap<
        frost::Identifier<C>,
        Vec<frost::keys::dkg::Round1Package<C>>,
    > = HashMap::new();

    // For each participant, perform the first part of the DKG protocol.
    // In practice, each participant will perform this on their own environments.
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let (secret_package, round1_package) = frost::keys::dkg::keygen_part1(
            participant_identifier,
            max_signers,
            min_signers,
            &mut rng,
        )
        .unwrap();

        // Store the participant's secret package for later use.
        // In practice each participant will store it in their own environment.
        round1_secret_packages.insert(participant_identifier, secret_package);

        // Send the round 1 package to all other participants. In this
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
                .or_insert_with(Vec::new)
                .push(round1_package.clone());
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
        let (round2_secret_package, round2_packages) = frost::keys::dkg::keygen_part2(
            round1_secret_packages
                .remove(&participant_identifier)
                .unwrap(),
            received_round1_packages
                .get(&participant_identifier)
                .unwrap(),
        )
        .expect("should work");

        // Store the participant's secret package for later use.
        // In practice each participant will store it in their own environment.
        round2_secret_packages.insert(participant_identifier, round2_secret_package);

        // "Send" the round 2 package to all other participants. In this
        // test this is simulated using a HashMap; in practice this will be
        // sent through some communication channel.
        // Note that, in contrast to the previous part, here each other participant
        // gets its own specific package.
        for round2_package in round2_packages {
            received_round2_packages
                .entry(round2_package.receiver_identifier)
                .or_insert_with(Vec::new)
                .push(round2_package);
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
    // For each participant, store the set of verifying keys of the other
    // participants. This is used to check if the set is correct for all
    // participants.
    // In practice, if there is a Coordinator, only they need to store the set.
    // If there is not, then all candidates must store their own sets.
    // The verifying keys are used to verify the signature shares produced
    // for each signature before being aggregated.
    let mut others_verifying_keys_by_participant = HashMap::new();

    // For each participant, perform the third part of the DKG protocol.
    // In practice, each participant will perform this on their own environments.
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let (key_package, others_verifying_keys) = frost::keys::dkg::keygen_part3(
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
        others_verifying_keys_by_participant.insert(participant_identifier, others_verifying_keys);
    }

    // Test if the set of verifying keys is correct for all participants.
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let public_key_package = others_verifying_keys_by_participant
            .get(&participant_identifier)
            .unwrap();
        for (identifier, verifying_key) in &public_key_package.signer_pubkeys {
            assert_eq!(
                verifying_keys.get(identifier).unwrap(),
                verifying_key,
                "the verifying key that participant {:?} computed for participant {:?} is not correct",
                participant_identifier,
                identifier
            );
        }
    }

    let pubkeys = frost::keys::PublicKeyPackage {
        signer_pubkeys: verifying_keys,
        group_public: group_public.unwrap(),
    };

    // Proceed with the signing test.
    check_sign(min_signers, key_packages, rng, pubkeys);
}
