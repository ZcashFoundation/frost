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

#[test]
fn check_sign_with_test_vectors() {
    let (
        key_packages,
        message,
        signer_commitments,
        group_binding_factor_input,
        group_binding_factor,
        signature_shares,
        signature,
    ) = parse_test_vectors();

    // Key generation
    for key_package in key_packages {
        assert_eq!(key_package.public, key_package.secret_share.into());
    }

    // Round one
    // for (i, signing_commitments) in signer_commitments {
    //     // compute nonce commitments from nonces
    // }

    // Round two
    let signing_package = frost::SigningPackage::new(signer_commitments, message);
}
