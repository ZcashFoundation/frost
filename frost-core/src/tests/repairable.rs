//! Test for Repairable Threshold Scheme

use debugless_unwrap::DebuglessUnwrap;
use rand_core::{CryptoRng, RngCore};
use serde_json::Value;

use crate::{
    frost::{
        self,
        keys::{
            generate_coefficients,
            repairable::compute_random_values,
            repairable::{compute_sum_of_random_values, recover_share},
            PublicKeyPackage, SecretShare, SigningShare,
        },
        Identifier,
    },
    Ciphersuite, Field, Group, Scalar,
};

/// Test RTS.
pub fn check_rts<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    // We want to test that recover share matches the original share

    // Compute shares

    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;
    let (shares, _pubkeys): (Vec<SecretShare<C>>, PublicKeyPackage<C>) =
        frost::keys::keygen_with_dealer(max_signers, min_signers, &mut rng).unwrap();

    // Try to recover a share

    // Signer 2 will lose their share
    // Signer 1, 4 and 5 will help signer 2 to recover their share

    let helpers: [Identifier<C>; 3] = [
        Identifier::try_from(1).unwrap(),
        Identifier::try_from(4).unwrap(),
        Identifier::try_from(5).unwrap(),
    ];
    //  For every helper i in helpers:

    let random_values = generate_coefficients::<C, R>(2, &mut rng);

    for i in [1usize, 4, 5] {
        // let identifier: Identifier<C> = Identifier::try_from(i as u16).unwrap();
        // pub fn compute_random_values(i, helpers, share_i, zeta_i) -> deltas_i
        let zeta_i = <<C::Group as Group>::Field>::one();
        let deltas_i = compute_random_values(&helpers, &shares[i - 1], zeta_i, &random_values);

        // Test if Sum of deltas_i = zeta_i * share _i
        let lhs = zeta_i * shares[i - 1].value.0;
        let mut rhs = <<C::Group as Group>::Field>::zero();
        for (_k, v) in deltas_i {
            rhs = rhs + v;
        }

        assert!(lhs == rhs);
    }
}

fn generate_scalar_from_byte_string<C: Ciphersuite>(
    bs: &str,
) -> <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar {
    let decoded = hex::decode(bs).unwrap();
    let out = <<C::Group as Group>::Field>::deserialize(&decoded.try_into().debugless_unwrap());
    out.unwrap()
}

/// Test compute_sum_of_random_values
pub fn check_compute_sum_of_random_values<C: Ciphersuite>(repair_share_helper_functions: &Value) {
    let values = &repair_share_helper_functions["scalar_generation"];

    let value_1 =
        generate_scalar_from_byte_string::<C>(values["random_scalar_1"].as_str().unwrap());
    let value_2 =
        generate_scalar_from_byte_string::<C>(values["random_scalar_2"].as_str().unwrap());
    let value_3 =
        generate_scalar_from_byte_string::<C>(values["random_scalar_3"].as_str().unwrap());

    let expected: Scalar<C> = compute_sum_of_random_values::<C>(&[value_1, value_2, value_3]);

    let actual: <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar =
        generate_scalar_from_byte_string::<C>(values["random_scalar_sum"].as_str().unwrap());

    assert!(actual == expected);
}

/// Test recover_share
pub fn check_recover_share<C: Ciphersuite, R: RngCore + CryptoRng>(
    mut rng: R,
    repair_share_helper_functions: &Value,
) {

    // Generate shares
    let max_signers = 5;
    let min_signers = 3;
    let (shares, _pubkeys): (Vec<SecretShare<C>>, PublicKeyPackage<C>) =
        frost::keys::keygen_with_dealer(max_signers, min_signers, &mut rng).unwrap();

    let sigmas: &Value = &repair_share_helper_functions["sigma_generation"];

    let sigma_1 = generate_scalar_from_byte_string::<C>(sigmas["sigma_1"].as_str().unwrap());
    let sigma_2 = generate_scalar_from_byte_string::<C>(sigmas["sigma_2"].as_str().unwrap());
    let sigma_3 = generate_scalar_from_byte_string::<C>(sigmas["sigma_3"].as_str().unwrap());
    let sigma_4 = generate_scalar_from_byte_string::<C>(sigmas["sigma_4"].as_str().unwrap());

    let commitment = (shares[0].commitment).clone();

    let expected = recover_share::<C>(
        &[sigma_1, sigma_2, sigma_3, sigma_4],
        Identifier::try_from(2).unwrap(),
        &commitment,
    );

    let actual_sigma: <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar =
        generate_scalar_from_byte_string::<C>(sigmas["sigma_sum"].as_str().unwrap());
    let actual: SecretShare<C> = SecretShare {
        identifier: Identifier::try_from(2).unwrap(),
        value: SigningShare(actual_sigma),
        commitment,
    };

    assert!(actual.identifier == expected.identifier);
}
