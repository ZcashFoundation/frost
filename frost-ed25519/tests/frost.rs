use curve25519_dalek::{edwards::EdwardsPoint, traits::Identity};
use frost_core::{Ciphersuite, Group};
use frost_ed25519::*;
use rand::thread_rng;

#[test]
fn check_sign_with_dealer() {
    let rng = thread_rng();

    frost_core::tests::check_sign_with_dealer::<Ed25519Sha512, _>(rng);
}

#[test]
fn check_sign_with_dkg() {
    let rng = thread_rng();

    frost_core::tests::check_sign_with_dkg::<Ed25519Sha512, _>(rng);
}

#[test]
fn check_batch_verify() {
    let rng = thread_rng();

    frost_core::tests::batch::batch_verify::<Ed25519Sha512, _>(rng);
}

#[test]
fn check_bad_batch_verify() {
    let rng = thread_rng();

    frost_core::tests::batch::bad_batch_verify::<Ed25519Sha512, _>(rng);
}

#[test]
fn check_deserialize_identity() {
    let encoded_identity = EdwardsPoint::identity().compress().to_bytes();

    let r = <<Ed25519Sha512 as Ciphersuite>::Group as Group>::deserialize(&encoded_identity);
    assert_eq!(r, Err(Error::InvalidIdentityElement));
}
