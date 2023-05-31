use rand::thread_rng;

use crate::*;

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
