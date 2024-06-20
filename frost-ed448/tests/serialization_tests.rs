#![cfg(feature = "serialization")]

mod helpers;

use frost_ed448::{
    keys::{
        dkg::{round1, round2},
        KeyPackage, PublicKeyPackage, SecretShare,
    },
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    SigningPackage,
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
fn check_round2_package_postcard_serialization() {
    let round2_package = samples::round2_package();
    let bytes: Vec<_> = round2_package.serialize().unwrap();
    assert_snapshot!(hex::encode(&bytes));
    assert_eq!(
        round2_package,
        round2::Package::deserialize(&bytes).unwrap()
    );
}
