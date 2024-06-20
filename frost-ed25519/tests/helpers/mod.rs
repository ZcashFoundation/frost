// Required since each integration test is compiled as a separated crate,
// and each one uses only part of the module.
#![allow(dead_code)]

pub mod samples;

use ed25519_dalek::Verifier;
use frost_ed25519::*;

// #[cfg(test)]
pub fn verify_signature(
    msg: &[u8],
    group_signature: frost_core::Signature<Ed25519Sha512>,
    group_pubkey: frost_core::VerifyingKey<Ed25519Sha512>,
) {
    let sig = {
        let bytes: [u8; 64] = group_signature.serialize().unwrap().try_into().unwrap();
        ed25519_dalek::Signature::from(bytes)
    };
    let pub_key = {
        let bytes = group_pubkey.serialize().unwrap().try_into().unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap()
    };
    // Check that signature validation has the expected result.
    assert!(pub_key.verify(msg, &sig).is_ok());
}
