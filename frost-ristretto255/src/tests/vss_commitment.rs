use serde_json::Value;
use std::sync::LazyLock;

use crate::*;

// Tests for serialization and deserialization VerifiableSecretSharingCommitment

static ELEMENTS: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../tests/helpers/elements.json").trim()).unwrap()
});

#[test]
fn check_serialize_vss_commitment() {
    let rng = rand_core::UnwrapErr(rand::rngs::SysRng);
    frost_core::tests::vss_commitment::check_serialize_vss_commitment::<Ristretto255Sha512, _>(rng);
}

#[test]
fn check_serialize_whole_vss_commitment() {
    let rng = rand_core::UnwrapErr(rand::rngs::SysRng);
    frost_core::tests::vss_commitment::check_serialize_whole_vss_commitment::<Ristretto255Sha512, _>(
        rng,
    );
}

#[test]
fn check_deserialize_vss_commitment() {
    let rng = rand_core::UnwrapErr(rand::rngs::SysRng);
    frost_core::tests::vss_commitment::check_deserialize_vss_commitment::<Ristretto255Sha512, _>(
        rng,
    );
}

#[test]
fn check_deserialize_whole_vss_commitment() {
    let rng = rand_core::UnwrapErr(rand::rngs::SysRng);
    frost_core::tests::vss_commitment::check_deserialize_whole_vss_commitment::<
        Ristretto255Sha512,
        _,
    >(rng);
}

#[test]
fn check_deserialize_vss_commitment_error() {
    let rng = rand_core::UnwrapErr(rand::rngs::SysRng);
    frost_core::tests::vss_commitment::check_deserialize_vss_commitment_error::<
        Ristretto255Sha512,
        _,
    >(rng, &ELEMENTS);
}

#[test]
fn check_deserialize_whole_vss_commitment_error() {
    let rng = rand_core::UnwrapErr(rand::rngs::SysRng);
    frost_core::tests::vss_commitment::check_deserialize_whole_vss_commitment_error::<
        Ristretto255Sha512,
        _,
    >(rng, &ELEMENTS);
}

#[test]
fn check_compute_public_key_package() {
    let rng = rand_core::UnwrapErr(rand::rngs::SysRng);
    frost_core::tests::vss_commitment::check_compute_public_key_package::<Ristretto255Sha512, _>(
        rng,
    );
}
