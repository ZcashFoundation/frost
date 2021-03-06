use std::{collections::HashMap, convert::TryFrom};

use frost_ristretto255::*;
use rand::thread_rng;

#[test]
fn check_sign_with_dealer() {
    let mut rng = thread_rng();

    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let numsigners = 5;
    let threshold = 3;
    let (shares, pubkeys) = keys::keygen_with_dealer(numsigners, threshold, &mut rng).unwrap();

    // Verifies the secret shares from the dealer
    let key_packages: Vec<keys::KeyPackage> = shares
        .into_iter()
        .map(|share| keys::KeyPackage::try_from(share).unwrap())
        .collect();

    let mut nonces: HashMap<u16, round1::SigningNonces> = HashMap::new();
    let mut commitments: HashMap<u16, round1::SigningCommitments> = HashMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    for participant_index in 1..(threshold + 1) {
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _threshold_.
        let (nonce, commitment) = round1::commit(
            participant_index as u16,
            key_packages
                .get((participant_index - 1) as usize)
                .unwrap()
                .secret_share(),
            &mut rng,
        );
        nonces.insert(participant_index as u16, nonce);
        commitments.insert(participant_index as u16, commitment);
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares: Vec<round2::SignatureShare> = Vec::new();
    let message = "message to sign".as_bytes();
    let comms = commitments.clone().into_values().collect();
    let signing_package = SigningPackage::new(comms, message.to_vec());

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    for participant_index in nonces.keys() {
        let key_package = key_packages
            .iter()
            .find(|key_package| *participant_index == key_package.index)
            .unwrap();

        let nonces_to_use = &nonces.get(participant_index).unwrap();

        // Each participant generates their signature share.
        let signature_share = round2::sign(&signing_package, nonces_to_use, key_package).unwrap();
        signature_shares.push(signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate (also verifies the signature shares)
    let group_signature_res = aggregate(&signing_package, &signature_shares[..], &pubkeys);

    assert!(group_signature_res.is_ok());

    let group_signature = group_signature_res.unwrap();

    // Check that the threshold signature can be verified by the group public
    // key (the verification key).
    assert!(pubkeys
        .group_public
        .verify(message, &group_signature)
        .is_ok());

    // Check that the threshold signature can be verified by the group public
    // key (the verification key) from SharePackage.group_public
    for (participant_index, _) in nonces.clone() {
        let key_package = key_packages.get(participant_index as usize).unwrap();

        assert!(key_package
            .group_public
            .verify(message, &group_signature)
            .is_ok());
    }
}
