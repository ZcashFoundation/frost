use crate::*;

#[test]
fn check_batch_verify() {
    let rng = rand_core::UnwrapErr(rand::rngs::SysRng);

    frost_core::tests::batch::batch_verify::<P256Sha256, _>(rng);
}

#[test]
fn check_bad_batch_verify() {
    let rng = rand_core::UnwrapErr(rand::rngs::SysRng);

    frost_core::tests::batch::bad_batch_verify::<P256Sha256, _>(rng);
}

#[test]
fn empty_batch_verify() {
    let rng = rand_core::UnwrapErr(rand::rngs::SysRng);

    frost_core::tests::batch::empty_batch_verify::<P256Sha256, _>(rng);
}
