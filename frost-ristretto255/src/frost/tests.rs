use std::{collections::HashMap, convert::TryFrom, str::FromStr};

use rand::thread_rng;

use crate::frost::{self, *};

mod vectors;

use vectors::RISTRETTO255_SHA512;

fn reconstruct_secret(secret_shares: Vec<SecretShare>) -> Result<Scalar, &'static str> {
    let numshares = secret_shares.len();

    if numshares < 1 {
        return Err("No secret_shares provided");
    }

    let mut lagrange_coeffs: Vec<Scalar> = Vec::with_capacity(numshares as usize);

    for i in 0..numshares {
        let mut num = Scalar::one();
        let mut den = Scalar::one();
        for j in 0..numshares {
            if j == i {
                continue;
            }
            num *= Scalar::from(secret_shares[j].index as u64);
            den *= Scalar::from(secret_shares[j].index as u64)
                - Scalar::from(secret_shares[i].index as u64);
        }
        if den == Scalar::zero() {
            return Err("Duplicate shares provided");
        }
        lagrange_coeffs.push(num * den.invert());
    }

    let mut secret = Scalar::zero();

    for i in 0..numshares {
        secret += lagrange_coeffs[i] * secret_shares[i].value.0;
    }

    Ok(secret)
}

/// This is testing that Shamir's secret sharing to compute and arbitrary
/// value is working.
#[test]
fn check_share_generation() {
    let mut rng = thread_rng();

    let mut bytes = [0; 64];
    rng.fill_bytes(&mut bytes);
    let secret = Secret(Scalar::from_bytes_mod_order_wide(&bytes));

    let _ = RISTRETTO_BASEPOINT_POINT * secret.0;

    let secret_shares = generate_secret_shares(&secret, 5, 3, rng).unwrap();

    for secret_share in secret_shares.iter() {
        assert_eq!(verify_secret_share(secret_share), Ok(()));
    }

    assert_eq!(reconstruct_secret(secret_shares).unwrap(), secret.0)
}

// #[test]
// fn check_sign_with_test_vectors() {
//     // let mut rng = thread_rng();
//     // let numsigners = 5;
//     // let threshold = 3;
//     // let (shares, pubkeys) = frost::keygen_with_dealer(numsigners, threshold, &mut rng).unwrap();

//     let config = &RISTRETTO255_SHA512["config"];
//     let inputs = &RISTRETTO255_SHA512["inputs"];
//     println!("{inputs}");

//     assert_eq!(hex::encode("test"), inputs["message"].as_str().unwrap());

//     let mut share_packages: Vec<SharePackage> =
//         Vec::with_capacity(config["NUM_SIGNERS"].as_u64().unwrap() as usize);

//     for (i, secret_share) in RISTRETTO255_SHA512["inputs"]["signers"]
//         .as_object()
//         .unwrap()
//     {
//         // TODO: parse test vector bytes into `SecretShare`, turn that .into() `SharePackage`

//         println!("{secret_share}");

//         let secret = Secret::try_from(secret_share["value"].into()).unwrap();
//         let signer_public = secret.into();

//         share_packages.push(SharePackage {
//             index: u64::from_str(i).unwrap(),
//             secret_share: secret_share.clone(),
//             public: signer_public,
//             group_public,
//         });

//         signer_pubkeys.insert(secret_share.index, signer_public);
//     }

//     // let mut nonces: HashMap<u64, Vec<frost::SigningNonces>> =
//     //     HashMap::with_capacity(threshold as usize);
//     // let mut commitments: Vec<frost::SigningCommitments> = Vec::with_capacity(threshold as usize);

//     // // Round 1, generating nonces and signing commitments for each participant.
//     // for participant_index in 1..(threshold + 1) {
//     //     // Generate one (1) nonce and one SigningCommitments instance for each
//     //     // participant, up to _threshold_.
//     //     let (nonce, commitment) = frost::preprocess(1, participant_index as u64, &mut rng);
//     //     nonces.insert(participant_index as u64, nonce);
//     //     commitments.push(commitment[0]);
//     // }

//     // // This is what the signature aggregator / coordinator needs to do:
//     // // - decide what message to sign
//     // // - take one (unused) commitment per signing participant
//     // let mut signature_shares: Vec<frost::SignatureShare> = Vec::with_capacity(threshold as usize);
//     // let message = "message to sign".as_bytes();
//     // let signing_package = frost::SigningPackage::new(commitments, message.to_vec());

//     // // Round 2: each participant generates their signature share
//     // for (participant_index, nonce) in &nonces {
//     //     let share_package = shares
//     //         .iter()
//     //         .find(|share| *participant_index == share.index)
//     //         .unwrap();
//     //     let nonce_to_use = nonce[0];
//     //     // Each participant generates their signature share.
//     //     let signature_share = frost::sign(&signing_package, &nonce_to_use, share_package).unwrap();
//     //     signature_shares.push(signature_share);
//     // }

//     // // The aggregator collects the signing shares from all participants and
//     // // generates the final signature.
//     // let group_signature_res = frost::aggregate(&signing_package, &signature_shares[..], &pubkeys);
//     // assert!(group_signature_res.is_ok());
//     // let group_signature = group_signature_res.unwrap();

//     // // Check that the threshold signature can be verified by the group public
//     // // key (aka verification key).
//     // assert!(pubkeys
//     //     .group_public
//     //     .verify(message, &group_signature)
//     //     .is_ok());

//     // let nonces_2 = nonces.clone();

//     // // Check that the threshold signature can be verified by the group public
//     // // key (aka verification key) from SharePackage.group_public
//     // for (participant_index, _) in nonces_2 {
//     //     let share_package = shares
//     //         .iter()
//     //         .find(|share| participant_index == share.index)
//     //         .unwrap();

//     //     assert!(share_package
//     //         .group_public
//     //         .verify(message, &group_signature)
//     //         .is_ok());
//     // }
// }
