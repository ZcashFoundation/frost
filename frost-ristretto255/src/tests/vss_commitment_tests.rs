use lazy_static::lazy_static;
use rand::thread_rng;
use serde_json::Value;

use crate::*;

// Tests for serialization and deserialization VerifiableSecretSharingCommitment

lazy_static! {
    pub static ref ELEMENTS: Value =
        serde_json::from_str(include_str!("../../tests/test_helpers/elements.json").trim())
            .unwrap();
}

#[test]
fn check_serialize_vss_commitment() {
    let rng = thread_rng();
    frost_core::tests::check_serialize_vss_commitment::<Ristretto255Sha512, _>(rng);
}

#[test]
fn check_deserialize_vss_commitment() {
    let rng = thread_rng();
    frost_core::tests::check_deserialize_vss_commitment::<Ristretto255Sha512, _>(rng);
}

#[test]
fn check_deserialize_vss_commitment_error() {
    let rng = thread_rng();
    frost_core::tests::check_deserialize_vss_commitment_error::<Ristretto255Sha512, _>(
        rng, &ELEMENTS,
    );
}
