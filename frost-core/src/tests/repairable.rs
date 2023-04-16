//! Test for Repairable Threshold Scheme

use debugless_unwrap::DebuglessUnwrap;
use rand_core::{CryptoRng, RngCore};
use serde_json::Value;

use crate::{
    frost::{
        self,
        keys::{
            repairable::{
                compute_lagrange_coefficient, repair_share_step_1, repair_share_step_2,
                repair_share_step_3,
            },
            PublicKeyPackage, SecretShare, SigningShare,
        },
        Identifier,
    },
    Ciphersuite, Field, Group, Scalar,
};

/// We want to test that recover share matches the original share
pub fn check_rts<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
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

    let helper_1 = &shares[0];
    let helper_4 = &shares[3];
    let helper_5 = &shares[4];
    let participant = &shares[1];

    let helpers: [Identifier<C>; 3] = [
        helper_1.identifier,
        helper_4.identifier,
        helper_5.identifier,
    ];

    // Each helper generates random values for each helper

    let helper_1_deltas = repair_share_step_1(
        &helpers,
        &shares[0],
        &mut rng,
        participant.identifier,
        helpers[0],
    );
    let helper_4_deltas = repair_share_step_1(
        &helpers,
        &shares[3],
        &mut rng,
        participant.identifier,
        helpers[1],
    );
    let helper_5_deltas = repair_share_step_1(
        &helpers,
        &shares[4],
        &mut rng,
        participant.identifier,
        helpers[2],
    );

    // Each helper calculates their sigma from the random values received from the other helpers

    let helper_1_sigma: Scalar<C> = repair_share_step_2::<C>(&[
        helper_1_deltas[&helpers[0]],
        helper_4_deltas[&helpers[0]],
        helper_5_deltas[&helpers[0]],
    ]);
    let helper_4_sigma: Scalar<C> = repair_share_step_2::<C>(&[
        helper_1_deltas[&helpers[1]],
        helper_4_deltas[&helpers[1]],
        helper_5_deltas[&helpers[1]],
    ]);
    let helper_5_sigma: Scalar<C> = repair_share_step_2::<C>(&[
        helper_1_deltas[&helpers[2]],
        helper_4_deltas[&helpers[2]],
        helper_5_deltas[&helpers[2]],
    ]);

    // The participant wishing to recover their share sums the sigmas sent from all helpers

    let participant_2_recovered_share = repair_share_step_3(
        &[helper_1_sigma, helper_4_sigma, helper_5_sigma],
        participant.identifier,
        &shares[1].commitment,
    );

    assert!(shares[1].secret() == participant_2_recovered_share.secret())
}

fn generate_scalar_from_byte_string<C: Ciphersuite>(
    bs: &str,
) -> <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar {
    let decoded = hex::decode(bs).unwrap();
    let out = <<C::Group as Group>::Field>::deserialize(&decoded.try_into().debugless_unwrap());
    out.unwrap()
}

/// Test repair_share_step_1
pub fn check_repair_share_step_1<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    // Compute shares

    let max_signers = 5;
    let min_signers = 3;
    let (shares, _pubkeys): (Vec<SecretShare<C>>, PublicKeyPackage<C>) =
        frost::keys::keygen_with_dealer(max_signers, min_signers, &mut rng).unwrap();

    // Signer 2 will lose their share
    // Signers (helpers) 1, 4 and 5 will help signer 2 (participant) to recover their share

    let helper_1 = &shares[0];
    let helper_4 = &shares[3];
    let helper_5 = &shares[4];
    let participant = &shares[1];

    let helpers: [Identifier<C>; 3] = [
        helper_1.identifier,
        helper_4.identifier,
        helper_5.identifier,
    ];

    // Generate deltas for helper 4
    let deltas = repair_share_step_1(
        &helpers,
        helper_4,
        &mut rng,
        participant.identifier,
        helpers[1],
    );

    let lagrange_coefficient =
        compute_lagrange_coefficient(&helpers, participant.identifier, helpers[1]);

    let mut rhs = <<C::Group as Group>::Field>::zero();
    for (_k, v) in deltas {
        rhs = rhs + v;
    }

    let lhs = lagrange_coefficient * helper_4.value.0;

    assert!(lhs == rhs)
}

/// Test repair_share_step_2
pub fn check_repair_share_step_2<C: Ciphersuite>(repair_share_helper_functions: &Value) {
    let values = &repair_share_helper_functions["scalar_generation"];

    let value_1 =
        generate_scalar_from_byte_string::<C>(values["random_scalar_1"].as_str().unwrap());
    let value_2 =
        generate_scalar_from_byte_string::<C>(values["random_scalar_2"].as_str().unwrap());
    let value_3 =
        generate_scalar_from_byte_string::<C>(values["random_scalar_3"].as_str().unwrap());

    let expected: Scalar<C> = repair_share_step_2::<C>(&[value_1, value_2, value_3]);

    let actual: <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar =
        generate_scalar_from_byte_string::<C>(values["random_scalar_sum"].as_str().unwrap());

    assert!(actual == expected);
}

/// Test repair_share
pub fn check_repair_share_step_3<C: Ciphersuite, R: RngCore + CryptoRng>(
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

    let expected = repair_share_step_3::<C>(
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

    assert!(actual.value == expected.value);
}
