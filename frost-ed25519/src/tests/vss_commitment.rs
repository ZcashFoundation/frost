use lazy_static::lazy_static;
use serde_json::Value;

use crate::*;

// Tests for serialization and deserialization VerifiableSecretSharingCommitment

lazy_static! {
    pub static ref ELEMENTS: Value =
        serde_json::from_str(include_str!("../../tests/helpers/elements.json").trim()).unwrap();
}

#[test]
fn check_serialize_vss_commitment() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::vss_commitment::check_serialize_vss_commitment::<Ed25519Sha512, _>(rng);
}

#[test]
fn check_serialize_whole_vss_commitment() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::vss_commitment::check_serialize_whole_vss_commitment::<Ed25519Sha512, _>(
        rng,
    );
}

#[test]
fn check_deserialize_vss_commitment() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::vss_commitment::check_deserialize_vss_commitment::<Ed25519Sha512, _>(rng);
}

#[test]
fn check_deserialize_whole_vss_commitment() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::vss_commitment::check_deserialize_whole_vss_commitment::<Ed25519Sha512, _>(
        rng,
    );
}

#[test]
fn check_deserialize_vss_commitment_error() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::vss_commitment::check_deserialize_vss_commitment_error::<Ed25519Sha512, _>(
        rng, &ELEMENTS,
    );
}

#[test]
fn check_deserialize_whole_vss_commitment_error() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::vss_commitment::check_deserialize_whole_vss_commitment_error::<
        Ed25519Sha512,
        _,
    >(rng, &ELEMENTS);
}

#[test]
fn check_compute_public_key_package() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::vss_commitment::check_compute_public_key_package::<Ed25519Sha512, _>(rng);
}
