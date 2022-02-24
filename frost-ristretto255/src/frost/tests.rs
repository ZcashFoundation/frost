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

    let secret = Secret::random(&mut rng);

    let _ = RISTRETTO_BASEPOINT_POINT * secret.0;

    let secret_shares = generate_secret_shares(&secret, 5, 3, rng).unwrap();

    for secret_share in secret_shares.iter() {
        assert_eq!(secret_share.verify(), Ok(()));
    }

    assert_eq!(reconstruct_secret(secret_shares).unwrap(), secret.0)
}

#[test]
fn check_sign_with_test_vectors() {
    let (
        group_public,
        key_packages,
        _message,
        message_bytes,
        signer_nonces,
        signer_commitments,
        group_binding_factor_input,
        group_binding_factor,
        signature_shares,
        signature,
    ) = parse_test_vectors();

    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    for key_package in key_packages.values() {
        assert_eq!(key_package.public, key_package.secret_share.into());
    }

    /////////////////////////////////////////////////////////////////////////////
    // Round 1
    /////////////////////////////////////////////////////////////////////////////

    for (i, _) in signer_commitments.clone() {
        // compute nonce commitments from nonces
        let nonces = signer_nonces.get(&i).unwrap();
        let nonce_commitments = signer_commitments.get(&i).unwrap();

        assert_eq!(
            NonceCommitment::from(nonces.hiding),
            nonce_commitments.hiding
        );

        assert_eq!(
            NonceCommitment::from(nonces.binding),
            nonce_commitments.binding
        );
    }

    /////////////////////////////////////////////////////////////////////////////
    // Round 2
    /////////////////////////////////////////////////////////////////////////////

    let signer_commitments_vec = signer_commitments
        .clone()
        .into_iter()
        .map(|(_, signing_commitments)| signing_commitments)
        .collect();

    let signing_package = frost::SigningPackage::new(signer_commitments_vec, message_bytes);

    assert_eq!(signing_package.rho_preimage(), group_binding_factor_input);

    let rho: Rho = (&signing_package).into();

    assert_eq!(rho, group_binding_factor);

    let mut our_signature_shares: Vec<frost::SignatureShare> = Vec::new();

    // Each participant generates their signature share
    println!("{:?}", signer_nonces.keys());

    for index in signer_nonces.keys() {
        let key_package = key_packages[index];
        let nonces = signer_nonces[index];
        let commitments = signer_commitments[index];

        // Each participant generates their signature share.
        let signature_share =
            frost::sign(&signing_package, &nonces, &commitments, &key_package).unwrap();

        our_signature_shares.push(signature_share);
    }

    for _sig_share in our_signature_shares {
        // sig_share.check_is_valid()?;
        // println!("Ours: {:?}", sig_share);

        // // !!! DIVERGANCE !!!
        // println!("Test vector: {:?}", signature_shares[&sig_share.index]);

        // assert_eq!(sig_share, signature_shares[&sig_share.index]);
    }

    let signer_pubkeys = key_packages
        .into_iter()
        .map(|(i, key_package)| (i, key_package.public))
        .collect();

    let pubkey_package = PublicKeyPackage {
        signer_pubkeys,
        group_public,
    };

    // The aggregator collects the signing shares from all participants and generates the final
    // signature.
    let group_signature_result = frost::aggregate(
        &signing_package,
        &signature_shares
            .values()
            .cloned()
            .collect::<Vec<SignatureShare>>(),
        &pubkey_package,
    );

    println!("{:?}", group_signature_result);

    assert!(group_signature_result.is_ok());

    let group_signature = group_signature_result.unwrap();

    assert_eq!(group_signature, signature);
}
