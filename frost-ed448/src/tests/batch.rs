use rand::thread_rng;

use crate::*;

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
