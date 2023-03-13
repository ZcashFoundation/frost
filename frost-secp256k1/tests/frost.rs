use frost_core::{Ciphersuite, Group, GroupError};
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
fn check_generate_deltas_to_repair_share() {
    let rng = thread_rng();

    frost_core::tests::repairable::check_generate_deltas_to_repair_share::<Secp256K1Sha256, _>(rng);
}

lazy_static! {
    pub static ref REPAIR_SHARE: Value =
        serde_json::from_str(include_str!("repair-share.json").trim()).unwrap();
}

#[test]
fn check_compute_sigmas_to_repair_share() {
    frost_core::tests::repairable::check_compute_sigmas_to_repair_share::<Secp256K1Sha256>(
        &REPAIR_SHARE,
    );
}

#[test]
fn check_repair_share() {
    let rng = thread_rng();
    frost_core::tests::repairable::check_repair_share::<Secp256K1Sha256, _>(rng, &REPAIR_SHARE);
}
