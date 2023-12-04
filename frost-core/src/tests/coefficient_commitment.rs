//! CoefficientCommitment functions

use std::convert::TryFrom;

use crate as frost;
use crate::{keys::CoefficientCommitment, tests::helpers::generate_element, Group};
use debugless_unwrap::DebuglessUnwrap;
use rand_core::{CryptoRng, RngCore};
use serde_json::Value;

use crate::Ciphersuite;

/// Test retrieving Element from CoefficientCommitment
pub fn check_serialization_of_coefficient_commitment<C: Ciphersuite, R: RngCore + CryptoRng>(
    mut rng: R,
) {
    let element = generate_element::<C, R>(&mut rng);

    let expected = <C::Group>::serialize(&element);

    let data = frost::keys::CoefficientCommitment::<C>(element).serialize();

    assert!(expected.as_ref() == data.as_ref());
}

/// Test create a CoefficientCommitment.
pub fn check_create_coefficient_commitment<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    let element = generate_element::<C, R>(&mut rng);

    let expected = CoefficientCommitment::<C>(element);

    let serialized_element = <C::Group>::serialize(&element);

    let coeff_commitment =
        frost::keys::CoefficientCommitment::<C>::deserialize(serialized_element).unwrap();

    assert!(expected == coeff_commitment);
}

/// Test error handling for creation of a coefficient commitment
pub fn check_create_coefficient_commitment_error<C: Ciphersuite + PartialEq>(
    commitment_helpers: &Value,
) {
    let values = &commitment_helpers["elements"];
    let serialized: <C::Group as Group>::Serialization =
        <C::Group as Group>::Serialization::try_from(
            hex::decode(values["invalid_element"].as_str().unwrap()).unwrap(),
        )
        .debugless_unwrap();

    let coeff_commitment = frost::keys::CoefficientCommitment::<C>::deserialize(serialized);

    assert!(coeff_commitment.is_err());
}

/// Test retrieve Element from CoefficientCommitment
pub fn check_get_value_of_coefficient_commitment<C: Ciphersuite, R: RngCore + CryptoRng>(
    mut rng: R,
) {
    let element = generate_element::<C, R>(&mut rng);

    let coeff_commitment = frost::keys::CoefficientCommitment::<C>(element);
    let value = coeff_commitment.value();

    assert!(value == element)
}
