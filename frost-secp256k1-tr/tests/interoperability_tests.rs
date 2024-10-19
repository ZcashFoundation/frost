use frost_secp256k1_tr::*;

use crate::Secp256K1Sha256TR;
use rand::thread_rng;

mod helpers;

#[test]
fn check_interoperability_in_regular_sign() {
    let mut rng = thread_rng();

    for _ in 0..256 {
        let signing_key = SigningKey::new(&mut rng);
        let verifying_key = signing_key.into();
        let signature = signing_key.sign(&mut rng, b"message");
        helpers::verify_signature(b"message", &signature, &verifying_key);
    }
}

#[test]
fn check_interoperability_in_sign_with_dkg() {
    let rng = thread_rng();

    // Test with multiple keys/signatures to better exercise the key generation
    // and the interoperability check. A smaller number of iterations is used
    // because DKG takes longer and otherwise the test would be too slow.
    for _ in 0..32 {
        let (message, group_signature, group_pubkey) =
            frost_core::tests::ciphersuite_generic::check_sign_with_dkg::<Secp256K1Sha256TR, _>(
                rng.clone(),
            );

        helpers::verify_signature(&message, &group_signature, &group_pubkey);
    }
}

#[test]
fn check_interoperability_in_sign_with_dealer() {
    let rng = thread_rng();

    // Test with multiple keys/signatures to better exercise the key generation
    // and the interoperability check.
    for _ in 0..256 {
        let (message, group_signature, group_pubkey) =
            frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<Secp256K1Sha256TR, _>(
                rng.clone(),
            );

        // Check that the threshold signature can be verified by the `ed25519_dalek` crate
        // public key (interoperability test)
        helpers::verify_signature(&message, &group_signature, &group_pubkey);
    }
}
