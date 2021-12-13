use rand::thread_rng;
use std::collections::HashMap;

use redjubjub::frost;

#[test]
fn check_sign_with_dealer() {
    let mut rng = thread_rng();
    let numsigners = 5;
    let threshold = 3;
    let (shares, pubkeys) = frost::keygen_with_dealer(numsigners, threshold, &mut rng).unwrap();

    let mut nonces: HashMap<u64, Vec<frost::SigningNonces>> =
        HashMap::with_capacity(threshold as usize);
    let mut commitments: Vec<frost::SigningCommitments> = Vec::with_capacity(threshold as usize);

    // Round 1, generating nonces and signing commitments for each participant.
    for participant_index in 1..(threshold + 1) {
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _threshold_.
        let (nonce, commitment) = frost::preprocess(1, participant_index as u64, &mut rng);
        nonces.insert(participant_index as u64, nonce);
        commitments.push(commitment[0]);
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares: Vec<frost::SignatureShare> = Vec::with_capacity(threshold as usize);
    let message = "message to sign".as_bytes();
    let signing_package = frost::SigningPackage {
        message: message.to_vec(),
        signing_commitments: commitments,
    };

    // Round 2: each participant generates their signature share
    for (participant_index, nonce) in nonces {
        let share_package = shares
            .iter()
            .find(|share| participant_index == share.index)
            .unwrap();
        let nonce_to_use = nonce[0];
        // Each participant generates their signature share.
        let signature_share = frost::sign(&signing_package, nonce_to_use, share_package).unwrap();
        signature_shares.push(signature_share);
    }

    // The aggregator collects the signing shares from all participants and
    // generates the final signature.
    let group_signature_res = frost::aggregate(&signing_package, &signature_shares[..], &pubkeys);
    assert!(group_signature_res.is_ok());
    let group_signature = group_signature_res.unwrap();

    // Check that the threshold signature can be verified by the group public
    // key (aka verification key).
    assert!(pubkeys
        .group_public
        .verify(&message, &group_signature)
        .is_ok());

    // TODO: also check that the SharePackage.group_public also verifies the group signature.
}
