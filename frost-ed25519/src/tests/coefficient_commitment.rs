use lazy_static::lazy_static;
use rand::thread_rng;
use serde_json::Value;

use crate::*;

// Tests for serialization and deserialization of CoefficientCommitment

lazy_static! {
    pub static ref ELEMENTS: Value =
        serde_json::from_str(include_str!("../../tests/helpers/elements.json").trim()).unwrap();
}

#[test]
fn check_serialization_of_coefficient_commitment() {
    let rng = thread_rng();
    frost_core::tests::coefficient_commitment::check_serialization_of_coefficient_commitment::<
        Ed25519Sha512,
        _,
    >(rng);
}

#[test]
fn check_create_coefficient_commitment() {
    let rng = thread_rng();
    frost_core::tests::coefficient_commitment::check_create_coefficient_commitment::<
        Ed25519Sha512,
        _,
    >(rng);
}
#[test]
fn check_create_coefficient_commitment_error() {
    frost_core::tests::coefficient_commitment::check_create_coefficient_commitment_error::<
        Ed25519Sha512,
    >(&ELEMENTS);
}

#[test]
fn check_get_value_of_coefficient_commitment() {
    let rng = thread_rng();

    frost_core::tests::coefficient_commitment::check_get_value_of_coefficient_commitment::<
        Ed25519Sha512,
        _,
    >(rng);
}
