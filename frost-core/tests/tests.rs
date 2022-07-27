use lazy_static::lazy_static;
use rand::thread_rng;
use serde_json::Value;

mod common;

use common::ciphersuite::*;

lazy_static! {
    pub static ref RISTRETTO255_SHA512: Value =
        serde_json::from_str(include_str!("common/vectors.json").trim())
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

// This allows checking that to_scalar() works for all possible inputs;
// but requires making to_scalar() public.
// #[test]
// fn test_identifier_to_scalar() {
//     type R = Ristretto255Sha512;

//     let one = <<<R as Ciphersuite>::Group as Group>::Field as Field>::one();
//     let mut sum = <<<R as Ciphersuite>::Group as Group>::Field as Field>::one();
//     for i in 1..0xFFFFu16 {
//         let identifier: Identifier<R> = i.try_into().unwrap();
//         assert_eq!(sum, identifier.to_scalar());
//         sum = sum + one;
//     }
// }
