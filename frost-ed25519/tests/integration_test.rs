use crate::Ed25519Sha512;
use frost_ed25519::*;
use lazy_static::lazy_static;
use rand::thread_rng;
use serde_json::Value;

mod helpers;

#[test]
fn check_sign_with_dkg() {
    let rng = thread_rng();

    // Test with multiple keys/signatures to better exercise the key generation
    // and the interoperability check. A smaller number of iterations is used
    // because DKG takes longer and otherwise the test would be too slow.
    for _ in 0..32 {
        let (msg, group_signature, group_pubkey) =
            frost_core::tests::ciphersuite_generic::check_sign_with_dkg::<Ed25519Sha512, _>(
                rng.clone(),
            );

        helpers::verify_signature(&msg, group_signature, group_pubkey);
    }
}

#[test]
fn check_rts() {
    let rng = thread_rng();

    frost_core::tests::repairable::check_rts::<Ed25519Sha512, _>(rng);
}

#[test]
fn check_sign_with_dealer() {
    let rng = thread_rng();

    // Test with multiple keys/signatures to better exercise the key generation
    // and the interoperability check.
    for _ in 0..256 {
        let (msg, group_signature, group_pubkey) =
            frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<Ed25519Sha512, _>(
                rng.clone(),
            );

        // Check that the threshold signature can be verified by the `ed25519_dalek` crate
        // public key (interoperability test)
        helpers::verify_signature(&msg, group_signature, group_pubkey);
    }
}

/// This is testing that Shamir's secret sharing to compute and arbitrary
/// value is working.
#[test]
fn check_share_generation_ed25519_sha512() {
    let rng = thread_rng();
    frost_core::tests::ciphersuite_generic::check_share_generation::<Ed25519Sha512, _>(rng);
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
    frost_core::tests::vectors::check_sign_with_test_vectors::<Ed25519Sha512>(&VECTORS);
    frost_core::tests::vectors::check_sign_with_test_vectors::<Ed25519Sha512>(
        &VECTORS_BIG_IDENTIFIER,
    );
}
