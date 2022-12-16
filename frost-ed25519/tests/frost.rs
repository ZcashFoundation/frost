use frost_core::{Ciphersuite, Group, GroupError};
use frost_ed25519::*;

use curve25519_dalek::{edwards::EdwardsPoint, traits::Identity};
use ed25519_dalek::Verifier;
use rand::thread_rng;

fn verify_signature(
    msg: &[u8],
    group_signature: frost_core::Signature<Ed25519Sha512>,
    group_pubkey: frost_core::VerifyingKey<Ed25519Sha512>,
) {
    let sig = {
        let bytes: [u8; 64] = group_signature.to_bytes();
        ed25519_dalek::Signature::from(bytes)
    };
    let pub_key = {
        let bytes = group_pubkey.to_bytes();
        ed25519_dalek::PublicKey::from_bytes(&bytes).unwrap()
    };
    // Check that signature validation has the expected result.
    assert!(pub_key.verify(msg, &sig).is_ok());
}

#[test]
fn check_sign_with_dealer() {
    let rng = thread_rng();

    // For the interoperability test it's better to test with multiple signatures
    for _ in 0..256 {
        let (msg, group_signature, group_pubkey) =
            frost_core::tests::check_sign_with_dealer::<Ed25519Sha512, _>(rng.clone());

        // Check that the threshold signature can be verified by the `ed25519_dalek` crate
        // public key (interoperability test)
        verify_signature(&msg, group_signature, group_pubkey);
    }
}

#[test]
fn check_sign_with_dkg() {
    let rng = thread_rng();

    let (msg, group_signature, group_pubkey) =
        frost_core::tests::check_sign_with_dkg::<Ed25519Sha512, _>(rng);

    verify_signature(&msg, group_signature, group_pubkey);
}

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

#[test]
fn check_deserialize_identity() {
    let encoded_identity = EdwardsPoint::identity().compress().to_bytes();

    let r = <Ed25519Sha512 as Ciphersuite>::Group::deserialize(&encoded_identity);
    assert_eq!(r, Err(GroupError::InvalidIdentityElement));
}

#[test]
fn check_deserialize_non_prime_order() {
    let encoded_point =
        hex::decode("0300000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .try_into()
            .unwrap();
    let r = <Ed25519Sha512 as Ciphersuite>::Group::deserialize(&encoded_point);
    assert_eq!(r, Err(GroupError::InvalidNonPrimeOrderElement));
}
