//! VerifiableSecretSharingCommitment functions

use crate::{
    keys::{CoefficientCommitment, VerifiableSecretSharingCommitment},
    tests::helpers::generate_element,
    Group,
};
use debugless_unwrap::DebuglessUnwrap;
use rand_core::{CryptoRng, RngCore};
use serde_json::Value;

use crate::keys::{generate_with_dealer, IdentifierList, PublicKeyPackage};
use crate::Ciphersuite;

/// Test serialize VerifiableSecretSharingCommitment
pub fn check_serialize_vss_commitment<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    // Generate test CoefficientCommitments

    // ---
    let input_1 = generate_element::<C, R>(&mut rng);
    let input_2 = generate_element::<C, R>(&mut rng);
    let input_3 = generate_element::<C, R>(&mut rng);

    let coeff_comms = vec![
        CoefficientCommitment::<C>::new(input_1),
        CoefficientCommitment::new(input_2),
        CoefficientCommitment::new(input_3),
    ];

    //    ---

    let expected = [
        <C::Group>::serialize(&input_1).unwrap(),
        <C::Group>::serialize(&input_2).unwrap(),
        <C::Group>::serialize(&input_3).unwrap(),
    ];

    let vss_commitment = VerifiableSecretSharingCommitment(coeff_comms)
        .serialize()
        .unwrap();

    assert!(expected.len() == vss_commitment.len());
    assert!(expected
        .iter()
        .zip(vss_commitment.iter())
        .all(|(e, c)| e.as_ref() == c));
}

/// Test deserialize VerifiableSecretSharingCommitment
pub fn check_deserialize_vss_commitment<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    // Generate test CoefficientCommitments

    // ---
    let input_1 = generate_element::<C, R>(&mut rng);
    let input_2 = generate_element::<C, R>(&mut rng);
    let input_3 = generate_element::<C, R>(&mut rng);

    let coeff_comms = vec![
        CoefficientCommitment::<C>::new(input_1),
        CoefficientCommitment::new(input_2),
        CoefficientCommitment::new(input_3),
    ];
    // ---

    let expected = VerifiableSecretSharingCommitment(coeff_comms);

    let data = vec![
        <C::Group>::serialize(&input_1).unwrap(),
        <C::Group>::serialize(&input_2).unwrap(),
        <C::Group>::serialize(&input_3).unwrap(),
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
        <C::Group>::serialize(&input_1).unwrap(),
        <C::Group>::serialize(&input_2).unwrap(),
        <C::Group>::serialize(&input_3).unwrap(),
        serialized,
    ];

    let vss_value = VerifiableSecretSharingCommitment::<C>::deserialize(data);

    assert!(vss_value.is_err());
}

/// Test computing the public key package from a list of commitments.
pub fn check_compute_public_key_package<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    let max_signers = 3;
    let min_signers = 2;
    let (secret_shares, public_key_package) =
        generate_with_dealer::<C, _>(max_signers, min_signers, IdentifierList::Default, &mut rng)
            .unwrap();

    let members = secret_shares.keys().copied().collect();
    let group_commitment = secret_shares.values().next().unwrap().commitment().clone();

    assert_eq!(
        public_key_package,
        PublicKeyPackage::from_commitment(&members, &group_commitment).unwrap()
    );
}
