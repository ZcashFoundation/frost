use crate::*;
use rand_core::TryRngCore;

#[test]
fn check_batch_verify() {
    let rng = rand::rngs::OsRng.unwrap_err();

    frost_core::tests::batch::batch_verify::<P256Sha256, _>(rng);
}

#[test]
fn check_bad_batch_verify() {
    let rng = rand::rngs::OsRng.unwrap_err();

    frost_core::tests::batch::bad_batch_verify::<P256Sha256, _>(rng);
}

#[test]
fn empty_batch_verify() {
    let rng = rand::rngs::OsRng.unwrap_err();

    frost_core::tests::batch::empty_batch_verify::<P256Sha256, _>(rng);
}
