use frost_ed448::*;
use lazy_static::lazy_static;
use rand::thread_rng;
use serde_json::Value;

#[test]
fn check_sign_with_dkg() {
    let rng = thread_rng();

    frost_core::tests::ciphersuite_generic::check_sign_with_dkg::<Ed448Shake256, _>(rng);
}

#[test]
fn check_rts() {
    let rng = thread_rng();

    frost_core::tests::repairable::check_rts::<Ed448Shake256, _>(rng);
}

#[test]
fn check_sign_with_dealer() {
    let rng = thread_rng();

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<Ed448Shake256, _>(rng);
}

/// This is testing that Shamir's secret sharing to compute and arbitrary
/// value is working.
#[test]
fn check_share_generation_ed448_shake256() {
    let rng = thread_rng();
    frost_core::tests::ciphersuite_generic::check_share_generation::<Ed448Shake256, _>(rng);
}

lazy_static! {
    pub static ref VECTORS: Value =
        serde_json::from_str(include_str!("../tests/helpers/vectors.json").trim())
            .expect("Test vector is valid JSON");
    pub static ref VECTORS_BIG_IDENTIFIER: Value =
        serde_json::from_str(include_str!("../tests/helpers/vectors-big-identifier.json").trim())
            .expect("Test vector is valid JSON");
}

#[test]
fn check_sign_with_test_vectors() {
    frost_core::tests::vectors::check_sign_with_test_vectors::<Ed448Shake256>(&VECTORS);
}

#[test]
fn check_sign_with_test_vectors_with_big_identifiers() {
    frost_core::tests::vectors::check_sign_with_test_vectors::<Ed448Shake256>(
        &VECTORS_BIG_IDENTIFIER,
    );
}

#[test]
fn check_error_culprit() {
    frost_core::tests::ciphersuite_generic::check_error_culprit::<Ed448Shake256>();
}

#[test]
fn check_identifier_derivation() {
    frost_core::tests::ciphersuite_generic::check_identifier_derivation::<Ed448Shake256>();
}

#[test]
fn check_sign_with_dealer_and_identifiers() {
    let rng = thread_rng();

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_and_identifiers::<
        Ed448Shake256,
        _,
    >(rng);
}

#[test]
fn check_sign_with_missing_identifier() {
    let rng = thread_rng();
    frost_core::tests::ciphersuite_generic::check_sign_with_missing_identifier::<Ed448Shake256, _>(
        rng,
    );
}
