use frost_secp256k1::*;
use lazy_static::lazy_static;
use rand::thread_rng;
use serde_json::Value;

#[test]
fn check_sign_with_dealer() {
    let rng = thread_rng();

    frost_core::tests::check_sign_with_dealer::<Secp256K1Sha256, _>(rng);
}

#[test]
fn check_sign_with_dkg() {
    let rng = thread_rng();

    frost_core::tests::check_sign_with_dkg::<Secp256K1Sha256, _>(rng);
}

#[test]
fn check_batch_verify() {
    let rng = thread_rng();

    frost_core::tests::batch::batch_verify::<Secp256K1Sha256, _>(rng);
}

#[test]
fn check_bad_batch_verify() {
    let rng = thread_rng();

    frost_core::tests::batch::bad_batch_verify::<Secp256K1Sha256, _>(rng);
}

#[test]
fn check_deserialize_identity() {
    // The identity is actually encoded as a single byte; but the API does not
    // allow us to change that. Try to send something similar.
    let encoded_identity = [0u8; 33];

    let r = <Secp256K1Sha256 as Ciphersuite>::Group::deserialize(&encoded_identity);
    assert_eq!(r, Err(GroupError::MalformedElement));
}

#[test]
fn check_deserialize_non_canonical() {
    let mut encoded_generator = <Secp256K1Sha256 as Ciphersuite>::Group::serialize(
        &<Secp256K1Sha256 as Ciphersuite>::Group::generator(),
    );

    let r = <Secp256K1Sha256 as Ciphersuite>::Group::deserialize(&encoded_generator);
    assert!(r.is_ok());

    // The first byte should be 0x02 or 0x03. Set other value to
    // create a non-canonical encoding.
    encoded_generator[0] = 0xFF;
    let r = <Secp256K1Sha256 as Ciphersuite>::Group::deserialize(&encoded_generator);
    assert_eq!(r, Err(GroupError::MalformedElement));

    // Besides the first byte, it is still possible to get non-canonical encodings.
    // This is x = p + 2 which is non-canonical and maps to a valid prime-order point.
    let encoded_point =
        hex::decode("02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc31")
            .unwrap()
            .try_into()
            .unwrap();
    let r = <Secp256K1Sha256 as Ciphersuite>::Group::deserialize(&encoded_point);
    assert_eq!(r, Err(GroupError::MalformedElement));
}

#[test]
fn check_repair_share_step_1() {
    let rng = thread_rng();

    frost_core::tests::repairable::check_repair_share_step_1::<Secp256K1Sha256, _>(rng);
}

lazy_static! {
    pub static ref REPAIR_SHARE: Value =
        serde_json::from_str(include_str!("repair-share.json").trim()).unwrap();
}

#[test]
fn check_repair_share_step_2() {
    frost_core::tests::repairable::check_repair_share_step_2::<Secp256K1Sha256>(&REPAIR_SHARE);
}

#[test]
fn check_repair_share() {
    let rng = thread_rng();
    frost_core::tests::repairable::check_repair_share_step_3::<Secp256K1Sha256, _>(
        rng,
        &REPAIR_SHARE,
    );
}

#[test]
fn check_rts() {
    let rng = thread_rng();

    frost_core::tests::repairable::check_rts::<Secp256K1Sha256, _>(rng);
}

#[test]
fn check_create_coefficient_commitment() {
    let valid_element = "02ceddafdf4a7f88885ab26b20d18edb7d4d9589812a6cf1a5a1a09d3808dae5d8";

    frost_core::tests::check_create_coefficient_commitment::<Secp256K1Sha256>(valid_element);

    let invalid_element = "123456afdf4a7f88885ab26b20d18edb7d4d9589812a6cf1a5a1a09d3808dae5d8";

    frost_core::tests::check_create_coefficient_commitment_error::<Secp256K1Sha256>(
        invalid_element,
    );
}

#[test]
fn check_get_value_of_coefficient_commitment() {
    let rng = thread_rng();

    frost_core::tests::check_get_value_of_coefficient_commitment::<Secp256K1Sha256, _>(rng);
}

lazy_static! {
    pub static ref ELEMENTS: Value =
        serde_json::from_str(include_str!("elements.json").trim()).unwrap();
}

#[test]
fn check_serialize_vss_commitment() {
    frost_core::tests::check_serialize_vss_commitment::<Secp256K1Sha256>(&ELEMENTS);
}

#[test]
fn check_deserialize_vss_commitment() {
    frost_core::tests::check_deserialize_vss_commitment::<Secp256K1Sha256>(&ELEMENTS);
}

#[test]
fn check_deserialize_vss_commitment_errors() {
    frost_core::tests::check_deserialize_vss_commitment_errors::<Secp256K1Sha256>(&ELEMENTS);
}
