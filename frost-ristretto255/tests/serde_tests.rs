#![cfg(feature = "serde")]

use std::collections::HashMap;

use frost_core::{
    frost::keys::{SigningShare, VerifyingShare},
    Ciphersuite, Group,
};
use frost_ristretto255::{
    keys::{
        dkg::{round1, round2},
        KeyPackage, PublicKeyPackage, SecretShare, VerifiableSecretSharingCommitment,
    },
    round1::{NonceCommitment, SigningCommitments},
    round2::{SignatureResponse, SignatureShare},
    Signature, SigningPackage, VerifyingKey,
};

type C = frost_ristretto255::Ristretto255Sha512;

fn build_sample_signing_commitments() -> SigningCommitments {
    let element1 = <C as Ciphersuite>::Group::generator();
    let element2 = element1 + element1;
    let serialized_element1 = <C as Ciphersuite>::Group::serialize(&element1);
    let serialized_element2 = <C as Ciphersuite>::Group::serialize(&element2);
    let hiding_nonce_commitment = NonceCommitment::from_bytes(serialized_element1).unwrap();
    let binding_nonce_commitment = NonceCommitment::from_bytes(serialized_element2).unwrap();
    let identifier = 42u16.try_into().unwrap();

    SigningCommitments::new(
        identifier,
        hiding_nonce_commitment,
        binding_nonce_commitment,
    )
}

#[test]
fn check_signing_commitments_serialization() {
    let commitments = build_sample_signing_commitments();

    let json = serde_json::to_string_pretty(&commitments).unwrap();
    println!("{}", json);

    let decoded_commitments: SigningCommitments = serde_json::from_str(&json).unwrap();
    assert!(commitments == decoded_commitments);

    let json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "hiding": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    let decoded_commitments: SigningCommitments = serde_json::from_str(json).unwrap();
    assert!(commitments == decoded_commitments);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Wrong ciphersuite
    let invalid_json = r#"{
      "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
      "hiding": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
      "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
      "ciphersuite": "FROST(Ed25519, SHA-512)"
    }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "hiding": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "foo": "0000000000000000000000000000000000000000000000000000000000000000",
        "hiding": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "foo": "0000000000000000000000000000000000000000000000000000000000000000",
        "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "hiding": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
        "extra": 1
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());
}

#[test]
fn check_signing_package_serialization() {
    let commitments = build_sample_signing_commitments();
    let message = "hello world".as_bytes();

    let signing_package = SigningPackage::new(vec![commitments], message);

    let json = serde_json::to_string_pretty(&signing_package).unwrap();
    println!("{}", json);

    let decoded_signing_package: SigningPackage = serde_json::from_str(&json).unwrap();
    assert!(signing_package == decoded_signing_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    let json = r#"{
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
          "hiding": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
          "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
          "ciphersuite": "FROST(ristretto255, SHA-512)"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "ciphersuite": "FROST(ristretto255, SHA-512)"
    }"#;
    let decoded_signing_package: SigningPackage = serde_json::from_str(json).unwrap();
    assert!(signing_package == decoded_signing_package);

    // Invalid identifier
    let invalid_json = r#"{
      "signing_commitments": {
        "0000000000000000000000000000000000000000000000000000000000000000": {
          "identifier": "0000000000000000000000000000000000000000000000000000000000000000",
          "hiding": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
          "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
          "ciphersuite": "FROST(ristretto255, SHA-512)"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "ciphersuite": "FROST(ristretto255, SHA-512)"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
          "foo": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
          "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
          "ciphersuite": "FROST(ristretto255, SHA-512)"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "ciphersuite": "FROST(ristretto255, SHA-512)"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
          "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
          "ciphersuite": "FROST(ristretto255, SHA-512)"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "ciphersuite": "FROST(ristretto255, SHA-512)"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
          "hiding": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
          "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
          "ciphersuite": "FROST(ristretto255, SHA-512)"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "extra": 1,
      "ciphersuite": "FROST(ristretto255, SHA-512)"
    }
    "#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());
}

#[test]
fn check_signature_share_serialization() {
    let identifier = 42u16.try_into().unwrap();
    let serialized_scalar =
        hex::decode("a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f")
            .unwrap()
            .try_into()
            .unwrap();
    let signature_response = SignatureResponse::from_bytes(serialized_scalar).unwrap();

    let signature_share = SignatureShare::new(identifier, signature_response);

    let json = serde_json::to_string_pretty(&signature_share).unwrap();
    println!("{}", json);

    let decoded_signature_share: SignatureShare = serde_json::from_str(&json).unwrap();
    assert!(signature_share == decoded_signature_share);

    let json = r#"{
      "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
      "signature": "a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
      "ciphersuite": "FROST(ristretto255, SHA-512)"
    }"#;
    let decoded_commitments: SignatureShare = serde_json::from_str(json).unwrap();
    assert!(signature_share == decoded_commitments);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "signature": "e660b88149e1dd06d7cace3c5ee32a71b4b718e2719583630ba916579fe8320d",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "foo": "e660b88149e1dd06d7cace3c5ee32a71b4b718e2719583630ba916579fe8320d",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",,
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "signature": "e660b88149e1dd06d7cace3c5ee32a71b4b718e2719583630ba916579fe8320d",
        "extra": 1,
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());
}

#[test]
fn check_secret_share_serialization() {
    let identifier = 42u16.try_into().unwrap();
    let serialized_scalar =
        hex::decode("a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f")
            .unwrap()
            .try_into()
            .unwrap();
    let serialized_element =
        hex::decode("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76")
            .unwrap()
            .try_into()
            .unwrap();
    let signing_share = SigningShare::from_bytes(serialized_scalar).unwrap();
    let vss_commitment =
        VerifiableSecretSharingCommitment::deserialize(vec![serialized_element]).unwrap();

    let secret_share = SecretShare::new(identifier, signing_share, vss_commitment);

    let json = serde_json::to_string_pretty(&secret_share).unwrap();
    println!("{}", json);

    let decoded_secret_share: SecretShare = serde_json::from_str(&json).unwrap();
    assert!(secret_share == decoded_secret_share);

    let json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "value": "a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ],
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    let decoded_secret_share: SecretShare = serde_json::from_str(json).unwrap();
    assert!(secret_share == decoded_secret_share);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "value": "a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ],
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "foo": "a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ],
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ],
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "value": "a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ],
        "extra": 1,
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());
}

#[test]
fn check_key_package_serialization() {
    let identifier = 42u16.try_into().unwrap();
    let serialized_scalar =
        hex::decode("a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f")
            .unwrap()
            .try_into()
            .unwrap();
    let serialized_element =
        hex::decode("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76")
            .unwrap()
            .try_into()
            .unwrap();
    let signing_share = SigningShare::from_bytes(serialized_scalar).unwrap();
    let verifying_share = VerifyingShare::from_bytes(serialized_element).unwrap();
    let verifying_key = VerifyingKey::from_bytes(serialized_element).unwrap();

    let key_package = KeyPackage::new(identifier, signing_share, verifying_share, verifying_key);

    let json = serde_json::to_string_pretty(&key_package).unwrap();
    println!("{}", json);

    let decoded_key_package: KeyPackage = serde_json::from_str(&json).unwrap();
    assert!(key_package == decoded_key_package);

    let json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "public": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "group_public": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    let decoded_key_package: KeyPackage = serde_json::from_str(json).unwrap();
    assert!(key_package == decoded_key_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "public": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "group_public": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "foo": "a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "public": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "group_public": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "public": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "group_public": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "public": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "group_public": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "extra_field": 1,
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());
}

#[test]
fn check_public_key_package_serialization() {
    let identifier = 42u16.try_into().unwrap();
    let serialized_element =
        hex::decode("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76")
            .unwrap()
            .try_into()
            .unwrap();
    let verifying_share = VerifyingShare::from_bytes(serialized_element).unwrap();
    let verifying_key = VerifyingKey::from_bytes(serialized_element).unwrap();

    let public_key_package = PublicKeyPackage::new(
        HashMap::from([(identifier, verifying_share)]),
        verifying_key,
    );

    let json = serde_json::to_string_pretty(&public_key_package).unwrap();
    println!("{}", json);

    let decoded_public_key_package: PublicKeyPackage = serde_json::from_str(&json).unwrap();
    assert!(public_key_package == decoded_public_key_package);

    let json = r#"{
        "signer_pubkeys": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        },
        "group_public": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    let decoded_public_key_package: PublicKeyPackage = serde_json::from_str(json).unwrap();
    assert!(public_key_package == decoded_public_key_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "signer_pubkeys": {
          "0000000000000000000000000000000000000000000000000000000000000000": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        },
        "group_public": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "signer_pubkeys": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        },
        "foo": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "signer_pubkeys": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        },
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "signer_pubkeys": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        },
        "group_public": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "extra": 1,
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());
}

#[test]
fn check_round1_package_serialization() {
    let identifier = 42u16.try_into().unwrap();
    let serialized_scalar: [u8; 32] =
        hex::decode("a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f")
            .unwrap()
            .try_into()
            .unwrap();
    let serialized_element: [u8; 32] =
        hex::decode("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76")
            .unwrap()
            .try_into()
            .unwrap();
    let serialized_signature: [u8; 64] = serialized_element
        .iter()
        .chain(serialized_scalar.iter())
        .cloned()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let vss_commitment =
        VerifiableSecretSharingCommitment::deserialize(vec![serialized_element]).unwrap();
    let signature = Signature::from_bytes(serialized_signature).unwrap();

    let round1_package = round1::Package::new(identifier, vss_commitment, signature);

    let json = serde_json::to_string_pretty(&round1_package).unwrap();
    println!("{}", json);

    let decoded_round1_package: round1::Package = serde_json::from_str(&json).unwrap();
    assert!(round1_package == decoded_round1_package);

    let json = r#"{
        "sender_identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ],
        "proof_of_knowledge": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    let decoded_round1_package: round1::Package = serde_json::from_str(json).unwrap();
    assert!(round1_package == decoded_round1_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "sender_identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ],
        "proof_of_knowledge": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "sender_identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ],
        "foo": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "sender_identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ],
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "sender_identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ],
        "proof_of_knowledge": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "extra": 1,
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());
}

#[test]
fn check_round2_package_serialization() {
    let identifier = 42u16.try_into().unwrap();
    let serialized_scalar: [u8; 32] =
        hex::decode("a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f")
            .unwrap()
            .try_into()
            .unwrap();
    let signing_share = SigningShare::from_bytes(serialized_scalar).unwrap();

    let round2_package = round2::Package::new(identifier, identifier, signing_share);

    let json = serde_json::to_string_pretty(&round2_package).unwrap();
    println!("{}", json);

    let decoded_round2_package: round2::Package = serde_json::from_str(&json).unwrap();
    assert!(round2_package == decoded_round2_package);

    let json = r#"{
        "sender_identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "receiver_identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    let decoded_round2_package: round2::Package = serde_json::from_str(json).unwrap();
    assert!(round2_package == decoded_round2_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "sender_identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "receiver_identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "sender_identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "foo": "2a00000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "sender_identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "sender_identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "receiver_identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "a0bdb9f6bf7b44c092dc285e66ee0484bce85c2d83babe03442510ab37603b0f",
        "extra": 1,
        "ciphersuite": "FROST(ristretto255, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());
}
