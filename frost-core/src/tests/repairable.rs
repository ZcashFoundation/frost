//! Test for Repairable Threshold Scheme

use alloc::collections::BTreeMap;

use debugless_unwrap::DebuglessUnwrap;
use rand_core::{CryptoRng, RngCore};
use serde_json::Value;

use crate as frost;
use crate::{
    compute_lagrange_coefficient,
    keys::{
        repairable::{repair_share_step_1, repair_share_step_2, repair_share_step_3},
        PublicKeyPackage, SecretShare, SigningShare,
    },
    Ciphersuite, Error, Field, Group, Identifier, Scalar,
};

/// We want to test that recovered share matches the original share
pub fn check_rts<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    // Compute shares

    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;
    let (shares, _pubkeys): (BTreeMap<Identifier<C>, SecretShare<C>>, PublicKeyPackage<C>) =
        frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )
        .unwrap();

    // Try to recover a share

    // Signer 2 will lose their share
    // Signer 1, 4 and 5 will help signer 2 to recover their share

    let helper_1 = &shares[&Identifier::try_from(1).unwrap()];
    let helper_4 = &shares[&Identifier::try_from(4).unwrap()];
    let helper_5 = &shares[&Identifier::try_from(5).unwrap()];
    let participant = &shares[&Identifier::try_from(2).unwrap()];

    let helpers: [Identifier<C>; 3] = [
        helper_1.identifier,
        helper_4.identifier,
        helper_5.identifier,
    ];

    // Each helper generates random values for each helper

    let helper_1_deltas =
        repair_share_step_1(&helpers, helper_1, &mut rng, participant.identifier).unwrap();
    let helper_4_deltas =
        repair_share_step_1(&helpers, helper_4, &mut rng, participant.identifier).unwrap();
    let helper_5_deltas =
        repair_share_step_1(&helpers, helper_5, &mut rng, participant.identifier).unwrap();

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

    let participant_recovered_share = repair_share_step_3(
        &[helper_1_sigma, helper_4_sigma, helper_5_sigma],
        participant.identifier,
        &participant.commitment,
    );

    // TODO: assert on commitment equality as well once updates have been made to VerifiableSecretSharingCommitment
    assert!(participant.signing_share() == participant_recovered_share.signing_share())
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
    let (shares, _pubkeys): (BTreeMap<Identifier<C>, SecretShare<C>>, PublicKeyPackage<C>) =
        frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )
        .unwrap();

    // Signer 2 will lose their share
    // Signers (helpers) 1, 4 and 5 will help signer 2 (participant) to recover their share

    let helper_1 = &shares[&Identifier::try_from(1).unwrap()];
    let helper_4 = &shares[&Identifier::try_from(4).unwrap()];
    let helper_5 = &shares[&Identifier::try_from(5).unwrap()];
    let participant = &shares[&Identifier::try_from(2).unwrap()];

    let helpers: [Identifier<C>; 3] = [
        helper_1.identifier,
        helper_4.identifier,
        helper_5.identifier,
    ];

    // Generate deltas for helper 4
    let deltas = repair_share_step_1(&helpers, helper_4, &mut rng, participant.identifier).unwrap();

    let lagrange_coefficient = compute_lagrange_coefficient(
        &helpers.iter().cloned().collect(),
        Some(participant.identifier),
        helpers[1],
    )
    .unwrap();

    let mut rhs = <<C::Group as Group>::Field>::zero();
    for (_k, v) in deltas {
        rhs = rhs + v;
    }

    let lhs = lagrange_coefficient * helper_4.signing_share.to_scalar();

    assert!(lhs == rhs)
}

/// Test repair_share_step_2
pub fn check_repair_share_step_2<C: Ciphersuite>(repair_share_helpers: &Value) {
    let values = &repair_share_helpers["scalar_generation"];

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
    repair_share_helpers: &Value,
) {
    // Generate shares
    let max_signers = 5;
    let min_signers = 3;
    let (shares, _pubkeys): (BTreeMap<Identifier<C>, SecretShare<C>>, PublicKeyPackage<C>) =
        frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )
        .unwrap();

    let sigmas: &Value = &repair_share_helpers["sigma_generation"];

    let sigma_1 = generate_scalar_from_byte_string::<C>(sigmas["sigma_1"].as_str().unwrap());
    let sigma_2 = generate_scalar_from_byte_string::<C>(sigmas["sigma_2"].as_str().unwrap());
    let sigma_3 = generate_scalar_from_byte_string::<C>(sigmas["sigma_3"].as_str().unwrap());
    let sigma_4 = generate_scalar_from_byte_string::<C>(sigmas["sigma_4"].as_str().unwrap());

    let commitment = (shares[&Identifier::try_from(1).unwrap()].commitment).clone();

    let expected = repair_share_step_3::<C>(
        &[sigma_1, sigma_2, sigma_3, sigma_4],
        Identifier::try_from(2).unwrap(),
        &commitment,
    );

    let actual_sigma: <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar =
        generate_scalar_from_byte_string::<C>(sigmas["sigma_sum"].as_str().unwrap());
    let actual: SecretShare<C> = SecretShare::new(
        Identifier::try_from(2).unwrap(),
        SigningShare::new(actual_sigma),
        commitment,
    );

    assert!(actual.signing_share == expected.signing_share);
}

/// Test repair share step 1 fails with invalid numbers of signers.
pub fn check_repair_share_step_1_fails_with_invalid_min_signers<
    C: Ciphersuite,
    R: RngCore + CryptoRng,
>(
    mut rng: R,
) {
    // Generate shares
    let max_signers = 3;
    let min_signers = 2; // This is to make sure this test fails at the right point
    let (shares, _pubkeys): (BTreeMap<Identifier<C>, SecretShare<C>>, PublicKeyPackage<C>) =
        frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )
        .unwrap();

    let helper = Identifier::try_from(3).unwrap();

    let out = repair_share_step_1(
        &[helper],
        &shares[&helper],
        &mut rng,
        Identifier::try_from(2).unwrap(),
    );

    assert!(out.is_err());
    assert!(out == Err(Error::InvalidMinSigners))
}
