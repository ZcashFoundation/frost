use std::{collections::HashMap, convert::TryFrom};

use frost_core::frost::{self, Identifier};
use rand::thread_rng;

mod common;

use common::ciphersuite::Ristretto255Sha512 as R;

#[test]
fn check_sign_with_dealer() {
    let mut rng = thread_rng();

    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let numsigners = 5;
    let threshold = 3;
    let (shares, pubkeys) =
        frost::keys::keygen_with_dealer(numsigners, threshold, &mut rng).unwrap();

    // Verifies the secret shares from the dealer
    let key_packages: HashMap<frost::Identifier<R>, frost::keys::KeyPackage<R>> = shares
        .into_iter()
        .map(|share| {
            (
                share.identifier,
                frost::keys::KeyPackage::try_from(share).unwrap(),
            )
        })
        .collect();

    let mut nonces: HashMap<Identifier<R>, frost::round1::SigningNonces<R>> = HashMap::new();
    let mut commitments: HashMap<Identifier<R>, frost::round1::SigningCommitments<R>> =
        HashMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    for participant_index in 1..(threshold as u16 + 1) {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _threshold_.
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
    let mut signature_shares: Vec<frost::round2::SignatureShare<R>> = Vec::new();
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
    // key (the verification key) from SharePackage.group_public
    for (participant_identifier, _) in nonces.clone() {
        let key_package = key_packages.get(&participant_identifier).unwrap();

        assert!(key_package
            .group_public
            .verify(message, &group_signature)
            .is_ok());
    }
}
