use rand::thread_rng;

use crate::frost::{self, *};

mod vectors;

use vectors::*;

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
//     let (
//         group_public,
//         key_packages,
//         message,
//         message_bytes,
//         signer_commitments,
//         group_binding_factor_input,
//         _group_binding_factor,
//         signature_shares,
//         signature,
//     ) = parse_test_vectors();

//     // Key generation
//     for key_package in key_packages.values() {
//         assert_eq!(key_package.public, key_package.secret_share.into());
//     }

//     // Round 1
//     // for (i, signing_commitments) in signer_commitments {
//     //     // compute nonce commitments from nonces
//     // }

//     // Round 2
//     let signing_package = frost::SigningPackage::new(signer_commitments, message_bytes);

//     assert_eq!(signing_package.rho_preimage(), group_binding_factor_input);

//     // Each participant generates their signature share
//     // TODO: needs the nonces from the test vectors
//     // for (participant_index, nonce) in &nonces {
//     //     let key_package = key_packages
//     //         .iter()
//     //         .find(|key_package| *participant_index == key_package.index)
//     //         .unwrap();
//     //     let nonce_to_use = nonce[0];
//     //     // Each participant generates their signature share.
//     //     let signature_share = frost::sign(&signing_package, &nonce_to_use, key_package).unwrap();
//     //     signature_shares.push(signature_share);
//     // }

//     let signer_pubkeys = key_packages
//         .into_iter()
//         .map(|(i, key_package)| (i, key_package.public))
//         .collect();

//     let pubkey_package = PublicKeyPackage {
//         signer_pubkeys,
//         group_public,
//     };

//     // The aggregator collects the signing shares from all participants and generates the final
//     // signature.
//     let group_signature_result = frost::aggregate(
//         &signing_package,
//         &signature_shares
//             .values()
//             .cloned()
//             .collect::<Vec<SignatureShare>>(),
//         &pubkey_package,
//     );

//     // println!("{:?}", group_signature_result);

//     assert!(group_signature_result.is_ok());

//     let group_signature = group_signature_result.unwrap();

//     assert_eq!(group_signature, signature);
// }
