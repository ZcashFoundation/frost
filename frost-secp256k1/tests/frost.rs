use frost_core::{Ciphersuite, Group, GroupError};
use frost_secp256k1::*;
use rand::thread_rng;

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

    let r = <<Secp256K1Sha256 as Ciphersuite>::Group as Group>::deserialize(&encoded_identity);
    assert_eq!(r, Err(GroupError::MalformedElement));
}
