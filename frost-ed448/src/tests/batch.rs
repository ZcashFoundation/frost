use crate::*;

#[test]
fn check_batch_verify() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::batch::batch_verify::<Ed448Shake256, _>(rng);
}

#[test]
fn check_bad_batch_verify() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::batch::bad_batch_verify::<Ed448Shake256, _>(rng);
}

#[test]
fn empty_batch_verify() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::batch::empty_batch_verify::<Ed448Shake256, _>(rng);
}
