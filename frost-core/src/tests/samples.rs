//! Generate sample, fixed instances of structs for testing.

use std::collections::HashMap;

use debugless_unwrap::DebuglessUnwrap;

use crate::{
    frost::keys::{SigningShare, VerifyingShare},
    Ciphersuite, Group, Scalar, Signature, VerifyingKey,
};
use crate::{
    frost::{
        keys::{
            dkg::{round1, round2},
            KeyPackage, PublicKeyPackage, SecretShare, VerifiableSecretSharingCommitment,
        },
        round1::{NonceCommitment, SigningCommitments},
        round2::{SignatureResponse, SignatureShare},
        SigningPackage,
    },
    Element, Field,
};

fn element1<C: Ciphersuite>() -> Element<C> {
    <C as Ciphersuite>::Group::generator()
}

fn element2<C: Ciphersuite>() -> Element<C> {
    element1::<C>() + element1::<C>()
}

fn scalar1<C: Ciphersuite>() -> Scalar<C> {
    let one = <<C as Ciphersuite>::Group as Group>::Field::one();
    let two = one + one;
    // To return a fixed non-small number, get the inverse of 2
    <<C as Ciphersuite>::Group as Group>::Field::invert(&two)
        .expect("nonzero elements have inverses")
}

/// Generate a sample SigningCommitments.
pub fn signing_commitments<C: Ciphersuite>() -> SigningCommitments<C> {
    let serialized_element1 = <C as Ciphersuite>::Group::serialize(&element1::<C>());
    let serialized_element2 = <C as Ciphersuite>::Group::serialize(&element2::<C>());
    let hiding_nonce_commitment = NonceCommitment::from_bytes(serialized_element1).unwrap();
    let binding_nonce_commitment = NonceCommitment::from_bytes(serialized_element2).unwrap();
    let identifier = 42u16.try_into().unwrap();

    SigningCommitments::new(
        identifier,
        hiding_nonce_commitment,
        binding_nonce_commitment,
    )
}

/// Generate a sample SigningPackage.
pub fn signing_package<C: Ciphersuite>() -> SigningPackage<C> {
    let commitments = vec![signing_commitments()];
    let message = "hello world".as_bytes();

    SigningPackage::new(commitments, message)
}

/// Generate a sample SignatureShare.
pub fn signature_share<C: Ciphersuite>() -> SignatureShare<C> {
    let identifier = 42u16.try_into().unwrap();
    let serialized_scalar = <<C as Ciphersuite>::Group as Group>::Field::serialize(&scalar1::<C>());
    let signature_response = SignatureResponse::from_bytes(serialized_scalar).unwrap();

    SignatureShare::new(identifier, signature_response)
}

/// Generate a sample SecretShare.
pub fn secret_share<C: Ciphersuite>() -> SecretShare<C> {
    let identifier = 42u16.try_into().unwrap();
    let serialized_scalar = <<C as Ciphersuite>::Group as Group>::Field::serialize(&scalar1::<C>());
    let serialized_element = <C as Ciphersuite>::Group::serialize(&element1::<C>());
    let signing_share = SigningShare::from_bytes(serialized_scalar).unwrap();
    let vss_commitment =
        VerifiableSecretSharingCommitment::deserialize(vec![serialized_element]).unwrap();

    SecretShare::new(identifier, signing_share, vss_commitment)
}

/// Generate a sample KeyPackage.
pub fn key_package<C: Ciphersuite>() -> KeyPackage<C> {
    let identifier = 42u16.try_into().unwrap();
    let serialized_scalar = <<C as Ciphersuite>::Group as Group>::Field::serialize(&scalar1::<C>());
    let serialized_element = <C as Ciphersuite>::Group::serialize(&element1::<C>());
    let signing_share = SigningShare::from_bytes(serialized_scalar).unwrap();
    let verifying_share = VerifyingShare::from_bytes(serialized_element).unwrap();
    let serialized_element = <C as Ciphersuite>::Group::serialize(&element1::<C>());
    let verifying_key = VerifyingKey::from_bytes(serialized_element).unwrap();

    KeyPackage::new(identifier, signing_share, verifying_share, verifying_key)
}

/// Generate a sample PublicKeyPackage.
pub fn public_key_package<C: Ciphersuite>() -> PublicKeyPackage<C> {
    let identifier = 42u16.try_into().unwrap();
    let serialized_element = <C as Ciphersuite>::Group::serialize(&element1::<C>());
    let verifying_share = VerifyingShare::from_bytes(serialized_element).unwrap();
    let serialized_element = <C as Ciphersuite>::Group::serialize(&element1::<C>());
    let verifying_key = VerifyingKey::from_bytes(serialized_element).unwrap();
    let signer_pubkeys = HashMap::from([(identifier, verifying_share)]);

    PublicKeyPackage::new(signer_pubkeys, verifying_key)
}

/// Generate a sample round1::Package.
pub fn round1_package<C: Ciphersuite>() -> round1::Package<C> {
    let identifier = 42u16.try_into().unwrap();
    let serialized_scalar = <<C as Ciphersuite>::Group as Group>::Field::serialize(&scalar1::<C>());
    let serialized_element = <C as Ciphersuite>::Group::serialize(&element1::<C>());
    let serialized_signature = serialized_element
        .as_ref()
        .iter()
        .chain(serialized_scalar.as_ref().iter())
        .cloned()
        .collect::<Vec<u8>>()
        .try_into()
        .debugless_unwrap();
    let vss_commitment =
        VerifiableSecretSharingCommitment::deserialize(vec![serialized_element]).unwrap();
    let signature = Signature::from_bytes(serialized_signature).unwrap();

    round1::Package::new(identifier, vss_commitment, signature)
}

/// Generate a sample round2::Package.
pub fn round2_package<C: Ciphersuite>() -> round2::Package<C> {
    let identifier = 42u16.try_into().unwrap();
    let serialized_scalar = <<C as Ciphersuite>::Group as Group>::Field::serialize(&scalar1::<C>());
    let signing_share = SigningShare::from_bytes(serialized_scalar).unwrap();

    round2::Package::new(identifier, identifier, signing_share)
}
