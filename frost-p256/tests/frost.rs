use frost_p256::*;
use lazy_static::lazy_static;
use rand::thread_rng;
use serde_json::Value;

#[test]
fn check_sign_with_dealer() {
    let rng = thread_rng();

    frost_core::tests::check_sign_with_dealer::<P256Sha256, _>(rng);
}

#[test]
fn check_sign_with_dkg() {
    let rng = thread_rng();

    frost_core::tests::check_sign_with_dkg::<P256Sha256, _>(rng);
}

#[test]
fn check_batch_verify() {
    let rng = thread_rng();

    frost_core::tests::batch::batch_verify::<P256Sha256, _>(rng);
}

#[test]
fn check_bad_batch_verify() {
    let rng = thread_rng();

    frost_core::tests::batch::bad_batch_verify::<P256Sha256, _>(rng);
}

lazy_static! {
    pub static ref REPAIR_SHARE: Value =
        serde_json::from_str(include_str!("repair-share.json").trim()).unwrap();
}

#[test]
fn check_repair_share_step_1() {
    let rng = thread_rng();

    frost_core::tests::repairable::check_repair_share_step_1::<P256Sha256, _>(rng);
}

#[test]
fn check_repair_share_step_2() {
    frost_core::tests::repairable::check_repair_share_step_2::<P256Sha256>(&REPAIR_SHARE);
}

#[test]
fn check_repair_share_step_3() {
    let rng = thread_rng();
    frost_core::tests::repairable::check_repair_share_step_3::<P256Sha256, _>(rng, &REPAIR_SHARE);
}

#[test]
fn check_rts() {
    let rng = thread_rng();

    frost_core::tests::repairable::check_rts::<P256Sha256, _>(rng);
}

/// Tests for serialization and deserialization of CoefficientCommitment and VerifiableSecretSharingCommitment

#[test]
fn check_serialization_of_coefficient_commitment() {
    let rng = thread_rng();
    frost_core::tests::check_serialization_of_coefficient_commitment::<P256Sha256, _>(rng);
}

#[test]
fn check_create_coefficient_commitment() {
    let rng = thread_rng();
    frost_core::tests::check_create_coefficient_commitment::<P256Sha256, _>(rng);
}
#[test]
fn check_create_coefficient_commitment_error() {
    frost_core::tests::check_create_coefficient_commitment_error::<P256Sha256>(&ELEMENTS);
}

#[test]
fn check_get_value_of_coefficient_commitment() {
    let rng = thread_rng();

    frost_core::tests::check_get_value_of_coefficient_commitment::<P256Sha256, _>(rng);
}

lazy_static! {
    pub static ref ELEMENTS: Value =
        serde_json::from_str(include_str!("elements.json").trim()).unwrap();
}

#[test]
fn check_serialize_vss_commitment() {
    let rng = thread_rng();
    frost_core::tests::check_serialize_vss_commitment::<P256Sha256, _>(rng);
}

#[test]
fn check_deserialize_vss_commitment() {
    let rng = thread_rng();
    frost_core::tests::check_deserialize_vss_commitment::<P256Sha256, _>(rng);
}

#[test]
fn check_deserialize_vss_commitment_error() {
    let rng = thread_rng();
    frost_core::tests::check_deserialize_vss_commitment_error::<P256Sha256, _>(rng, &ELEMENTS);
}
