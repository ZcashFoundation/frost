//! VerifiableSecretSharingCommitment functions

use std::convert::TryFrom;

use crate::{
    frost::keys::{CoefficientCommitment, VerifiableSecretSharingCommitment},
    tests::helpers::generate_element,
    Group,
};
use debugless_unwrap::DebuglessUnwrap;
use rand_core::{CryptoRng, RngCore};
use serde_json::Value;

use crate::frost::keys::{compute_public_key_package, generate_with_dealer, IdentifierList};
use crate::Ciphersuite;

/// Test serialize VerifiableSecretSharingCommitment
pub fn check_serialize_vss_commitment<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    // Generate test CoefficientCommitments

    // ---
    let input_1 = generate_element::<C, R>(&mut rng);
    let input_2 = generate_element::<C, R>(&mut rng);
    let input_3 = generate_element::<C, R>(&mut rng);

    let coeff_comms = vec![
        CoefficientCommitment::<C>(input_1),
        CoefficientCommitment(input_2),
        CoefficientCommitment(input_3),
    ];

    //    ---

    let expected = vec![
        <C::Group>::serialize(&input_1),
        <C::Group>::serialize(&input_2),
        <C::Group>::serialize(&input_3),
    ];

    let vss_commitment = VerifiableSecretSharingCommitment(coeff_comms).serialize();

    assert!(expected.len() == vss_commitment.len());
    assert!(expected
        .iter()
        .zip(vss_commitment.iter())
        .all(|(e, c)| e.as_ref() == c.as_ref()));
}

/// Test deserialize VerifiableSecretSharingCommitment
pub fn check_deserialize_vss_commitment<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    // Generate test CoefficientCommitments

    // ---
    let input_1 = generate_element::<C, R>(&mut rng);
    let input_2 = generate_element::<C, R>(&mut rng);
    let input_3 = generate_element::<C, R>(&mut rng);

    let coeff_comms = vec![
        CoefficientCommitment::<C>(input_1),
        CoefficientCommitment(input_2),
        CoefficientCommitment(input_3),
    ];
    // ---

    let expected = VerifiableSecretSharingCommitment(coeff_comms);

    let data = vec![
        <C::Group>::serialize(&input_1),
        <C::Group>::serialize(&input_2),
        <C::Group>::serialize(&input_3),
    ];

    let vss_value = VerifiableSecretSharingCommitment::deserialize(data);

    assert!(vss_value.is_ok());
    assert!(expected == vss_value.unwrap());
}

/// Test deserialize VerifiableSecretSharingCommitment error
pub fn check_deserialize_vss_commitment_error<C: Ciphersuite, R: RngCore + CryptoRng>(
    mut rng: R,
    commitment_helpers: &Value,
) {
    // Generate test CoefficientCommitments

    // ---
    let values = &commitment_helpers["elements"];

    let input_1 = generate_element::<C, R>(&mut rng);
    let input_2 = generate_element::<C, R>(&mut rng);
    let input_3 = generate_element::<C, R>(&mut rng);

    let serialized: <C::Group as Group>::Serialization =
        <C::Group as Group>::Serialization::try_from(
            hex::decode(values["invalid_element"].as_str().unwrap()).unwrap(),
        )
        .debugless_unwrap();
    // ---

    let data = vec![
        <C::Group>::serialize(&input_1),
        <C::Group>::serialize(&input_2),
        <C::Group>::serialize(&input_3),
        serialized,
    ];

    let vss_value = VerifiableSecretSharingCommitment::<C>::deserialize(data);

    assert!(vss_value.is_err());
}

/// Test computing the public key package from a list of commitments.
pub fn check_compute_public_key_package<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    const MAX_SIGNERS: u16 = 3;
    const MIN_SIGNERS: u16 = 2;
    let identifiers = crate::frost::keys::default_identifiers(MAX_SIGNERS);
    let mut commitments = std::collections::HashMap::new();
    let mut verifying_shares = std::collections::HashMap::new();
    let mut public_key = <C::Group>::identity();
    for identifier in &identifiers {
        let (secret_shares_i, public_key_package_i) = generate_with_dealer::<C, _>(
            MAX_SIGNERS,
            MIN_SIGNERS,
            IdentifierList::Custom(&identifiers),
            &mut rng,
        )
        .unwrap();
        for identifier in &identifiers {
            let entry = verifying_shares
                .entry(*identifier)
                .or_insert_with(|| <C::Group>::identity());
            *entry = *entry
                + public_key_package_i
                    .signer_pubkeys()
                    .get(identifier)
                    .unwrap()
                    .to_element();
        }
        public_key = public_key + public_key_package_i.group_public().to_element();
        commitments.insert(
            *identifier,
            secret_shares_i
                .get(identifier)
                .unwrap()
                .commitment()
                .clone(),
        );
    }
    let public_key_package = compute_public_key_package::<C>(&commitments);
    assert!(public_key == public_key_package.group_public().to_element());
    for identifier in &identifiers {
        assert!(
            *verifying_shares.get(identifier).unwrap()
                == public_key_package
                    .signer_pubkeys()
                    .get(identifier)
                    .unwrap()
                    .to_element(),
        )
    }
}
