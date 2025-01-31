use crate::Ed25519Sha512;
use frost_ed25519::*;

mod helpers;

#[test]
fn check_interoperability_in_sign_with_dkg() {
    let rng = rand::rngs::OsRng;

    // Test with multiple keys/signatures to better exercise the key generation
    // and the interoperability check. A smaller number of iterations is used
    // because DKG takes longer and otherwise the test would be too slow.
    for _ in 0..32 {
        let (msg, group_signature, group_pubkey) =
            frost_core::tests::ciphersuite_generic::check_sign_with_dkg::<Ed25519Sha512, _>(rng);

        helpers::verify_signature(&msg, group_signature, group_pubkey);
    }
}

#[test]
fn check_interoperability_in_sign_with_dealer() {
    let rng = rand::rngs::OsRng;

    // Test with multiple keys/signatures to better exercise the key generation
    // and the interoperability check.
    for _ in 0..256 {
        let (msg, group_signature, group_pubkey) =
            frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<Ed25519Sha512, _>(rng);

        // Check that the threshold signature can be verified by the `ed25519_dalek` crate
        // public key (interoperability test)
        helpers::verify_signature(&msg, group_signature, group_pubkey);
    }
}
