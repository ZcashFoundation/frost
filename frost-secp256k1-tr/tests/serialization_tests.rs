#![cfg(feature = "serialization")]

mod helpers;

use frost_secp256k1_tr::{
    SigningPackage,
    keys::{
        KeyPackage, PublicKeyPackage, SecretShare,
        dkg::{round1, round2},
    },
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};

use helpers::samples;
use insta::assert_snapshot;

#[test]
fn check_signing_nonces_postcard_serialization() {
    let nonces = samples::signing_nonces();
    let bytes: Vec<_> = nonces.serialize().unwrap();
    assert_snapshot!(hex::encode(&bytes));
    assert_eq!(nonces, SigningNonces::deserialize(&bytes).unwrap());
}

#[test]
fn check_signing_commitments_postcard_serialization() {
    let commitments = samples::signing_commitments();
    let bytes: Vec<_> = commitments.serialize().unwrap();
    assert_snapshot!(hex::encode(&bytes));
    assert_eq!(
        commitments,
        SigningCommitments::deserialize(&bytes).unwrap()
    );
}

#[test]
fn check_signing_package_postcard_serialization() {
    let signing_package = samples::signing_package();
    let bytes: Vec<_> = signing_package.serialize().unwrap();
    assert_snapshot!(hex::encode(&bytes));
    assert_eq!(
        signing_package,
        SigningPackage::deserialize(&bytes).unwrap()
    );
}

#[test]
fn check_signature_share_postcard_serialization() {
    let signature_share = samples::signature_share();
    let bytes = signature_share.serialize();
    assert_snapshot!(hex::encode(&bytes));
    assert_eq!(
        signature_share,
        SignatureShare::deserialize(&bytes).unwrap()
    );
}
#[test]
fn check_secret_share_postcard_serialization() {
    let secret_share = samples::secret_share();
    let bytes: Vec<_> = secret_share.serialize().unwrap();
    assert_snapshot!(hex::encode(&bytes));
    assert_eq!(secret_share, SecretShare::deserialize(&bytes).unwrap());
}

#[test]
fn check_key_package_postcard_serialization() {
    let key_package = samples::key_package();
    let bytes: Vec<_> = key_package.serialize().unwrap();
    assert_snapshot!(hex::encode(&bytes));
    assert_eq!(key_package, KeyPackage::deserialize(&bytes).unwrap());
}

#[test]
fn check_public_key_package_postcard_serialization() {
    let public_key_package = samples::public_key_package();
    let bytes: Vec<_> = public_key_package.serialize().unwrap();
    assert_snapshot!(hex::encode(&bytes));
    assert_eq!(
        public_key_package,
        PublicKeyPackage::deserialize(&bytes).unwrap()
    );
}

#[test]
fn check_public_key_package_new_postcard_serialization() {
    let public_key_package = samples::public_key_package_new();
    let bytes: Vec<_> = public_key_package.serialize().unwrap();
    assert_snapshot!(hex::encode(&bytes));
    assert_eq!(
        public_key_package,
        PublicKeyPackage::deserialize(&bytes).unwrap()
    );
}

#[test]
fn check_round1_secret_package_postcard_serialization() {
    let round1_secret_package = samples::round1_secret_package();
    let bytes: Vec<_> = round1_secret_package.serialize().unwrap();
    assert_snapshot!(hex::encode(&bytes));
    assert_eq!(
        round1_secret_package,
        round1::SecretPackage::deserialize(&bytes).unwrap()
    );
}

#[test]
fn check_round1_package_postcard_serialization() {
    let round1_package = samples::round1_package();
    let bytes: Vec<_> = round1_package.serialize().unwrap();
    assert_snapshot!(hex::encode(&bytes));
    assert_eq!(
        round1_package,
        round1::Package::deserialize(&bytes).unwrap()
    );
}

#[test]
fn check_round2_secret_package_postcard_serialization() {
    let round2_secret_package = samples::round2_secret_package();
    let bytes: Vec<_> = round2_secret_package.serialize().unwrap();
    assert_snapshot!(hex::encode(&bytes));
    assert_eq!(
        round2_secret_package,
        round2::SecretPackage::deserialize(&bytes).unwrap()
    );
}

#[test]
fn check_round2_package_postcard_serialization() {
    let round2_package = samples::round2_package();
    let bytes: Vec<_> = round2_package.serialize().unwrap();
    assert_snapshot!(hex::encode(&bytes));
    assert_eq!(
        round2_package,
        round2::Package::deserialize(&bytes).unwrap()
    );
}

#[test]
fn check_postcard_deserialization_rejects_trailing_bytes() {
    fn with_trailing_bytes(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.extend_from_slice(b"trailing");
        bytes
    }

    let bytes = with_trailing_bytes(samples::signing_nonces().serialize().unwrap());
    assert!(SigningNonces::deserialize(&bytes).is_err());

    let bytes = with_trailing_bytes(samples::signing_commitments().serialize().unwrap());
    assert!(SigningCommitments::deserialize(&bytes).is_err());

    let bytes = with_trailing_bytes(samples::signing_package().serialize().unwrap());
    assert!(SigningPackage::deserialize(&bytes).is_err());

    let bytes = with_trailing_bytes(samples::signature_share().serialize());
    assert!(SignatureShare::deserialize(&bytes).is_err());

    let bytes = with_trailing_bytes(samples::secret_share().serialize().unwrap());
    assert!(SecretShare::deserialize(&bytes).is_err());

    let bytes = with_trailing_bytes(samples::key_package().serialize().unwrap());
    assert!(KeyPackage::deserialize(&bytes).is_err());

    let bytes = with_trailing_bytes(samples::public_key_package().serialize().unwrap());
    assert!(PublicKeyPackage::deserialize(&bytes).is_err());

    let bytes = with_trailing_bytes(samples::public_key_package_new().serialize().unwrap());
    assert!(PublicKeyPackage::deserialize(&bytes).is_err());

    let bytes = with_trailing_bytes(samples::round1_secret_package().serialize().unwrap());
    assert!(round1::SecretPackage::deserialize(&bytes).is_err());

    let bytes = with_trailing_bytes(samples::round1_package().serialize().unwrap());
    assert!(round1::Package::deserialize(&bytes).is_err());

    let bytes = with_trailing_bytes(samples::round2_secret_package().serialize().unwrap());
    assert!(round2::SecretPackage::deserialize(&bytes).is_err());

    let bytes = with_trailing_bytes(samples::round2_package().serialize().unwrap());
    assert!(round2::Package::deserialize(&bytes).is_err());
}
