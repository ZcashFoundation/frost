use lazy_static::lazy_static;
use rand::thread_rng;
use serde_json::Value;

use crate::*;

lazy_static! {
    pub static ref RISTRETTO255_SHA512: Value =
        serde_json::from_str(include_str!("tests/vectors.json").trim())
            .expect("Test vector is valid JSON");
}

/// This is testing that Shamir's secret sharing to compute and arbitrary
/// value is working.
#[test]
fn check_share_generation_ristretto255_sha512() {
    let rng = thread_rng();
    frost_core::tests::check_share_generation::<Ristretto255Sha512, _>(rng);
}

#[test]
fn check_sign_with_test_vectors() {
    frost_core::tests::vectors::check_sign_with_test_vectors::<Ristretto255Sha512>(
        &RISTRETTO255_SHA512,
    )
}
