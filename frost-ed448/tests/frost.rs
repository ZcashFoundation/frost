use ed448_goldilocks::curve::ExtendedPoint;
use frost_core::{Ciphersuite, Group};
use frost_ed448::*;
use rand::thread_rng;

#[test]
fn check_sign_with_dealer() {
    let rng = thread_rng();

    frost_core::tests::check_sign_with_dealer::<Ed448Shake256, _>(rng);
}

#[test]
fn check_sign_with_dkg() {
    let rng = thread_rng();

    frost_core::tests::check_sign_with_dkg::<Ed448Shake256, _>(rng);
}

// TODO: make batching work for larger scalars
// #[test]
#[allow(unused)]
fn check_batch_verify() {
    let rng = thread_rng();

    frost_core::tests::batch::batch_verify::<Ed448Shake256, _>(rng);
}

// TODO: make batching work for larger scalars
// #[test]
#[allow(unused)]
fn check_bad_batch_verify() {
    let rng = thread_rng();

    frost_core::tests::batch::bad_batch_verify::<Ed448Shake256, _>(rng);
}

#[test]
fn check_deserialize_identity() {
    let encoded_identity = ExtendedPoint::identity().compress().0;

    let r = <<Ed448Shake256 as Ciphersuite>::Group as Group>::deserialize(&encoded_identity);
    assert_eq!(r, Err(Error::InvalidIdentityElement));
}
