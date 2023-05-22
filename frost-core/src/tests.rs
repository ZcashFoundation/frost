//! Ciphersuite-generic test functions.
use std::{collections::HashMap, convert::TryFrom};

use crate::{
    frost::{
        self,
        keys::{CoefficientCommitment, VerifiableSecretSharingCommitment},
    },
    Field, Group, GroupError, Signature, VerifyingKey,
};
use debugless_unwrap::DebuglessUnwrap;
use rand_core::{CryptoRng, RngCore};
use serde_json::Value;

use crate::Ciphersuite;

pub mod batch;
pub mod proptests;
pub mod repairable;
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
pub fn check_sign_with_dealer<C: Ciphersuite, R: RngCore + CryptoRng>(
    mut rng: R,
) -> (Vec<u8>, Signature<C>, VerifyingKey<C>) {
    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;
    let (shares, pubkeys) =
        frost::keys::keygen_with_dealer(max_signers, min_signers, &mut rng).unwrap();

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
    pubkeys: frost::keys::PublicKeyPackage<C>,
) -> (Vec<u8>, Signature<C>, VerifyingKey<C>) {
    let mut nonces: HashMap<frost::Identifier<C>, frost::round1::SigningNonces<C>> = HashMap::new();
    let mut commitments: HashMap<frost::Identifier<C>, frost::round1::SigningCommitments<C>> =
        HashMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    for participant_index in 1..(min_signers + 1) {
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
    let mut signature_shares = Vec::new();
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

    (message.to_owned(), group_signature, pubkeys.group_public)
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
        Vec<frost::keys::dkg::round1::Package<C>>,
    > = HashMap::new();

    // For each participant, perform the first part of the DKG protocol.
    // In practice, each participant will perform this on their own environments.
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let (secret_package, round1_package) =
            frost::keys::dkg::part1(participant_identifier, max_signers, min_signers, &mut rng)
                .unwrap();

        // Store the participant's secret package for later use.
        // In practice each participant will store it in their own environment.
        round1_secret_packages.insert(participant_identifier, secret_package);

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
        let (round2_secret_package, round2_packages) = frost::keys::dkg::part2(
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

    let pubkeys = frost::keys::PublicKeyPackage {
        signer_pubkeys: verifying_keys,
        group_public: group_public.unwrap(),
    };

    // Proceed with the signing test.
    check_sign(min_signers, key_packages, rng, pubkeys)
}

/// Test creation of a CoefficientCommitment. This effectively parses an Element into a CoefficientCommitment.
pub fn check_create_coefficient_commitment<C: Ciphersuite + PartialEq>(input: &str) {
    let serialized: <C::Group as Group>::Serialization =
        <C::Group as Group>::Serialization::try_from(hex::decode(input).unwrap())
            .debugless_unwrap();

    let element = <C::Group as Group>::deserialize(&serialized).unwrap();

    let expected = CoefficientCommitment::<C>(element);

    let coeff_commitment = frost::keys::CoefficientCommitment::<C>::new(serialized).unwrap();

    assert!(coeff_commitment.0 == expected.0);
}

/// Test error handling for creation of a coefficient commitment
pub fn check_create_coefficient_commitment_error<C: Ciphersuite + PartialEq>(input: &str) {
    let serialized: <C::Group as Group>::Serialization =
        <C::Group as Group>::Serialization::try_from(hex::decode(input).unwrap())
            .debugless_unwrap();

    let coeff_commitment = frost::keys::CoefficientCommitment::<C>::new(serialized);

    assert!(coeff_commitment.is_err());
    assert!(coeff_commitment == Err(GroupError::MalformedElement.into()))
}

/// Test retrieving Element from CoefficientCommitment
pub fn check_get_value_of_coefficient_commitment<C: Ciphersuite, R: RngCore + CryptoRng>(
    mut rng: R,
) {
    let scalar = <<C::Group as Group>::Field>::random(&mut rng);
    let element = <C::Group>::generator() * scalar;

    let coeff_commitment = frost::keys::CoefficientCommitment::<C>(element);
    let value = coeff_commitment.value();

    assert!(value == element)
}

/// Test retrieving CoefficientCommitments from VerifiableSecretSharingCommitment
pub fn check_get_value_of_vss_commitment<C: Ciphersuite>(commitment_helper_functions: &Value) {
    let values = &commitment_helper_functions["elements"];

    // Generate test CoefficientCommitments

    // ---
    let input_1 = values["element_1"].as_str().unwrap();
    let input_2 = values["element_2"].as_str().unwrap();
    let input_3 = values["element_3"].as_str().unwrap();

    let comm_1_serialized =
        <C::Group as Group>::Serialization::try_from(hex::decode(input_1).unwrap())
            .debugless_unwrap();
    let comm_2_serialized: <C::Group as Group>::Serialization =
        <C::Group as Group>::Serialization::try_from(hex::decode(input_2).unwrap())
            .debugless_unwrap();
    let comm_3_serialized: <C::Group as Group>::Serialization =
        <C::Group as Group>::Serialization::try_from(hex::decode(input_3).unwrap())
            .debugless_unwrap();

    let comm_1 = frost::keys::CoefficientCommitment::<C>::new(comm_1_serialized).unwrap();
    let comm_2 = frost::keys::CoefficientCommitment::<C>::new(comm_2_serialized).unwrap();
    let comm_3 = frost::keys::CoefficientCommitment::<C>::new(comm_3_serialized).unwrap();
    // ---

    let vss_commitment =
        VerifiableSecretSharingCommitment(vec![comm_1, comm_2, comm_3]).serialize();

    let num_of_commitments = hex::encode("3");

    let expected = num_of_commitments + input_1 + input_2 + input_3;

    assert!(vss_commitment == expected)
}
