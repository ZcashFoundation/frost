use std::collections::HashMap;
use std::str::FromStr;

use hex;
use lazy_static::lazy_static;
use serde_json::Value;

use crate::frost::*;

lazy_static! {
    pub static ref RISTRETTO255_SHA512: Value =
        serde_json::from_str(include_str!("vectors.json").trim())
            .expect("Test vector is valid JSON");
}

pub fn parse_test_vectors() {
    let config = &RISTRETTO255_SHA512["config"];
    let inputs = &RISTRETTO255_SHA512["inputs"];

    println!("{inputs}");

    assert_eq!(hex::encode("test"), inputs["message"].as_str().unwrap());

    let mut signer_pubkeys: HashMap<u64, Public> = HashMap::new();

    let mut key_packages: Vec<KeyPackage> = Vec::new();

    let possible_signers = RISTRETTO255_SHA512["inputs"]["signers"]
        .as_object()
        .unwrap()
        .iter();

    for (i, secret_share) in possible_signers {
        let secret = Secret::from_hex(secret_share["signer_share"].as_str().unwrap()).unwrap();
        let signer_public = secret.into();

        let key_package = KeyPackage {
            index: u64::from_str(i).unwrap(),
            secret_share: secret,
            public: signer_public,
            group_public: VerificationKey::from_hex(inputs["group_public_key"].as_str().unwrap())
                .unwrap(),
        };

        key_packages.push(key_package);

        signer_pubkeys.insert(u64::from_str(i).unwrap(), signer_public);
    }

    // let mut nonces: HashMap<u64, Vec<frost::SigningNonces>> =
    //     HashMap::with_capacity(threshold as usize);
    // let mut commitments: Vec<frost::SigningCommitments> = Vec::with_capacity(threshold as usize);

    // // Round 1, generating nonces and signing commitments for each participant.
    // for participant_index in 1..(threshold + 1) {
    //     // Generate one (1) nonce and one SigningCommitments instance for each
    //     // participant, up to _threshold_.
    //     let (nonce, commitment) = frost::preprocess(1, participant_index as u64, &mut rng);
    //     nonces.insert(participant_index as u64, nonce);
    //     commitments.push(commitment[0]);
    // }

    // // This is what the signature aggregator / coordinator needs to do:
    // // - decide what message to sign
    // // - take one (unused) commitment per signing participant
    // let mut signature_shares: Vec<frost::SignatureShare> = Vec::with_capacity(threshold as usize);
    // let message = "message to sign".as_bytes();
    // let signing_package = frost::SigningPackage::new(commitments, message.to_vec());

    // // Round 2: each participant generates their signature share
    // for (participant_index, nonce) in &nonces {
    //     let share_package = shares
    //         .iter()
    //         .find(|share| *participant_index == share.index)
    //         .unwrap();
    //     let nonce_to_use = nonce[0];
    //     // Each participant generates their signature share.
    //     let signature_share = frost::sign(&signing_package, &nonce_to_use, share_package).unwrap();
    //     signature_shares.push(signature_share);
    // }

    // // The aggregator collects the signing shares from all participants and
    // // generates the final signature.
    // let group_signature_res = frost::aggregate(&signing_package, &signature_shares[..], &pubkeys);
}
