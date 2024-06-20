//! Generate sample, fixed instances of structs for testing.

use std::collections::BTreeMap;

use frost_core::{round1::Nonce, Ciphersuite, Element, Group, Scalar};
use frost_ed448::{
    keys::{
        dkg::{round1, round2},
        KeyPackage, PublicKeyPackage, SecretShare, SigningShare, VerifiableSecretSharingCommitment,
        VerifyingShare,
    },
    round1::{NonceCommitment, SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Field, Signature, SigningPackage, VerifyingKey,
};

type C = frost_ed448::Ed448Shake256;

fn element1() -> Element<C> {
    <C as Ciphersuite>::Group::generator()
}

fn element2() -> Element<C> {
    element1() + element1()
}

fn scalar1() -> Scalar<C> {
    let one = <<C as Ciphersuite>::Group as Group>::Field::one();
    let three = one + one + one;
    // To return a fixed non-small number, get the inverse of 3
    <<C as Ciphersuite>::Group as Group>::Field::invert(&three)
        .expect("nonzero elements have inverses")
}

/// Generate a sample SigningCommitments.
pub fn signing_nonces() -> SigningNonces {
    let serialized_scalar1 = <<C as Ciphersuite>::Group as Group>::Field::serialize(&scalar1());
    let serialized_scalar2 = <<C as Ciphersuite>::Group as Group>::Field::serialize(&scalar1());
    let hiding_nonce = Nonce::deserialize(serialized_scalar1.as_ref()).unwrap();
    let binding_nonce = Nonce::deserialize(serialized_scalar2.as_ref()).unwrap();

    SigningNonces::from_nonces(hiding_nonce, binding_nonce)
}

/// Generate a sample SigningCommitments.
pub fn signing_commitments() -> SigningCommitments {
    let serialized_element1 = <C as Ciphersuite>::Group::serialize(&element1()).unwrap();
    let serialized_element2 = <C as Ciphersuite>::Group::serialize(&element2()).unwrap();
    let hiding_nonce_commitment =
        NonceCommitment::deserialize(serialized_element1.as_ref()).unwrap();
    let binding_nonce_commitment =
        NonceCommitment::deserialize(serialized_element2.as_ref()).unwrap();

    SigningCommitments::new(hiding_nonce_commitment, binding_nonce_commitment)
}

/// Generate a sample SigningPackage.
pub fn signing_package() -> SigningPackage {
    let identifier = 42u16.try_into().unwrap();
    let commitments = BTreeMap::from([(identifier, signing_commitments())]);
    let message = "hello world".as_bytes();

    SigningPackage::new(commitments, message)
}

/// Generate a sample SignatureShare.
pub fn signature_share() -> SignatureShare {
    let serialized_scalar = <<C as Ciphersuite>::Group as Group>::Field::serialize(&scalar1());

    SignatureShare::deserialize(serialized_scalar.as_ref()).unwrap()
}

/// Generate a sample SecretShare.
pub fn secret_share() -> SecretShare {
    let identifier = 42u16.try_into().unwrap();
    let serialized_scalar = <<C as Ciphersuite>::Group as Group>::Field::serialize(&scalar1());
    let serialized_element = <C as Ciphersuite>::Group::serialize(&element1()).unwrap();
    let signing_share = SigningShare::deserialize(serialized_scalar.as_ref()).unwrap();
    let vss_commitment =
        VerifiableSecretSharingCommitment::deserialize(vec![serialized_element]).unwrap();

    SecretShare::new(identifier, signing_share, vss_commitment)
}

/// Generate a sample KeyPackage.
pub fn key_package() -> KeyPackage {
    let identifier = 42u16.try_into().unwrap();
    let serialized_scalar = <<C as Ciphersuite>::Group as Group>::Field::serialize(&scalar1());
    let serialized_element = <C as Ciphersuite>::Group::serialize(&element1()).unwrap();
    let signing_share = SigningShare::deserialize(serialized_scalar.as_ref()).unwrap();
    let verifying_share = VerifyingShare::deserialize(serialized_element.as_ref()).unwrap();
    let serialized_element = <C as Ciphersuite>::Group::serialize(&element1()).unwrap();
    let verifying_key = VerifyingKey::deserialize(serialized_element.as_ref()).unwrap();

    KeyPackage::new(identifier, signing_share, verifying_share, verifying_key, 2)
}

/// Generate a sample PublicKeyPackage.
pub fn public_key_package() -> PublicKeyPackage {
    let identifier = 42u16.try_into().unwrap();
    let serialized_element = <C as Ciphersuite>::Group::serialize(&element1()).unwrap();
    let verifying_share = VerifyingShare::deserialize(serialized_element.as_ref()).unwrap();
    let serialized_element = <C as Ciphersuite>::Group::serialize(&element1()).unwrap();
    let verifying_key = VerifyingKey::deserialize(serialized_element.as_ref()).unwrap();
    let verifying_shares = BTreeMap::from([(identifier, verifying_share)]);

    PublicKeyPackage::new(verifying_shares, verifying_key)
}

/// Generate a sample round1::Package.
pub fn round1_package() -> round1::Package {
    let serialized_scalar = <<C as Ciphersuite>::Group as Group>::Field::serialize(&scalar1());
    let serialized_element = <C as Ciphersuite>::Group::serialize(&element1()).unwrap();
    let serialized_signature = serialized_element
        .as_ref()
        .iter()
        .chain(serialized_scalar.as_ref().iter())
        .cloned()
        .collect::<Vec<u8>>();
    let vss_commitment =
        VerifiableSecretSharingCommitment::deserialize(vec![serialized_element]).unwrap();
    let signature = Signature::deserialize(&serialized_signature).unwrap();

    round1::Package::new(vss_commitment, signature)
}

/// Generate a sample round2::Package.
pub fn round2_package() -> round2::Package {
    let serialized_scalar = <<C as Ciphersuite>::Group as Group>::Field::serialize(&scalar1());
    let signing_share = SigningShare::deserialize(serialized_scalar.as_ref()).unwrap();

    round2::Package::new(signing_share)
}
