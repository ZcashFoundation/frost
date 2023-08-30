#![cfg(feature = "serde")]

mod helpers;

use frost_ed25519::{
    keys::{
        dkg::{round1, round2},
        KeyPackage, PublicKeyPackage, SecretShare,
    },
    round1::SigningCommitments,
    round2::SignatureShare,
    SigningPackage,
};

use helpers::samples;

#[test]
fn check_signing_commitments_serialization() {
    let commitments = samples::signing_commitments();

    let json = serde_json::to_string_pretty(&commitments).unwrap();
    println!("{}", json);

    let decoded_commitments: SigningCommitments = serde_json::from_str(&json).unwrap();
    assert!(commitments == decoded_commitments);

    let json = r#"{
        "hiding": "5866666666666666666666666666666666666666666666666666666666666666",
        "binding": "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    let decoded_commitments: SigningCommitments = serde_json::from_str(json).unwrap();
    assert!(commitments == decoded_commitments);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Wrong ciphersuite
    let invalid_json = r#"{
      "hiding": "5866666666666666666666666666666666666666666666666666666666666666",
      "binding": "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
      "ciphersuite": "FROST(Wrong, SHA-512)"
    }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "hiding": "5866666666666666666666666666666666666666666666666666666666666666",
        "binding": "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022"
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "foo": "5866666666666666666666666666666666666666666666666666666666666666",
        "binding": "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022"
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "binding": "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022"
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Extra field is ignored
    let invalid_json = r#"{
        "hiding": "5866666666666666666666666666666666666666666666666666666666666666",
        "binding": "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
        "ciphersuite": "FROST(Ed25519, SHA-512)",
        "extra": 1
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_ok());
}

#[test]
fn check_signing_package_serialization() {
    let signing_package = samples::signing_package();

    let json = serde_json::to_string_pretty(&signing_package).unwrap();
    println!("{}", json);

    let decoded_signing_package: SigningPackage = serde_json::from_str(&json).unwrap();
    assert!(signing_package == decoded_signing_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    let json = r#"{
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "hiding": "5866666666666666666666666666666666666666666666666666666666666666",
          "binding": "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
          "ciphersuite": "FROST(Ed25519, SHA-512)"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "ciphersuite": "FROST(Ed25519, SHA-512)"
    }"#;
    let decoded_signing_package: SigningPackage = serde_json::from_str(json).unwrap();
    assert!(signing_package == decoded_signing_package);

    // Invalid identifier
    let invalid_json = r#"{
      "signing_commitments": {
        "0000000000000000000000000000000000000000000000000000000000000000": {
          "hiding": "5866666666666666666666666666666666666666666666666666666666666666",
          "binding": "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
          "ciphersuite": "FROST(Ed25519, SHA-512)"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "ciphersuite": "FROST(Ed25519, SHA-512)"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "foo": "5866666666666666666666666666666666666666666666666666666666666666",
          "binding": "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
          "ciphersuite": "FROST(Ed25519, SHA-512)"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "ciphersuite": "FROST(Ed25519, SHA-512)"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "binding": "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
          "ciphersuite": "FROST(Ed25519, SHA-512)"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "ciphersuite": "FROST(Ed25519, SHA-512)"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Extra field is ignored
    let invalid_json = r#"{
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "hiding": "5866666666666666666666666666666666666666666666666666666666666666",
          "binding": "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
          "ciphersuite": "FROST(Ed25519, SHA-512)"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "extra": 1,
      "ciphersuite": "FROST(Ed25519, SHA-512)"
    }
    "#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_ok());
}

#[test]
fn check_signature_share_serialization() {
    let signature_share = samples::signature_share();

    let json = serde_json::to_string_pretty(&signature_share).unwrap();
    println!("{}", json);

    let decoded_signature_share: SignatureShare = serde_json::from_str(&json).unwrap();
    assert!(signature_share == decoded_signature_share);

    let json = r#"{
      "share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
      "ciphersuite": "FROST(Ed25519, SHA-512)"
    }"#;
    let decoded_commitments: SignatureShare = serde_json::from_str(json).unwrap();
    assert!(signature_share == decoded_commitments);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "foo": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Extra field is ignored
    let invalid_json = r#"{
        "share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "extra": 1,
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_ok());
}

#[test]
fn check_secret_share_serialization() {
    let secret_share = samples::secret_share();

    let json = serde_json::to_string_pretty(&secret_share).unwrap();
    println!("{}", json);

    let decoded_secret_share: SecretShare = serde_json::from_str(&json).unwrap();
    assert!(secret_share == decoded_secret_share);

    let json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "value": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "commitment": [
          "5866666666666666666666666666666666666666666666666666666666666666"
        ],
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    let decoded_secret_share: SecretShare = serde_json::from_str(json).unwrap();
    assert!(secret_share == decoded_secret_share);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "value": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "commitment": [
          "5866666666666666666666666666666666666666666666666666666666666666"
        ],
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "foo": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "commitment": [
          "5866666666666666666666666666666666666666666666666666666666666666"
        ],
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "commitment": [
          "5866666666666666666666666666666666666666666666666666666666666666"
        ],
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Extra field is ignored
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "value": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "commitment": [
          "5866666666666666666666666666666666666666666666666666666666666666"
        ],
        "extra": 1,
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_ok());
}

#[test]
fn check_key_package_serialization() {
    let key_package = samples::key_package();

    let json = serde_json::to_string_pretty(&key_package).unwrap();
    println!("{}", json);

    let decoded_key_package: KeyPackage = serde_json::from_str(&json).unwrap();
    assert!(key_package == decoded_key_package);

    let json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "public": "5866666666666666666666666666666666666666666666666666666666666666",
        "group_public": "5866666666666666666666666666666666666666666666666666666666666666",
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    let decoded_key_package: KeyPackage = serde_json::from_str(json).unwrap();
    assert!(key_package == decoded_key_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "public": "5866666666666666666666666666666666666666666666666666666666666666",
        "group_public": "5866666666666666666666666666666666666666666666666666666666666666",
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "foo": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "public": "5866666666666666666666666666666666666666666666666666666666666666",
        "group_public": "5866666666666666666666666666666666666666666666666666666666666666",
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "public": "5866666666666666666666666666666666666666666666666666666666666666",
        "group_public": "5866666666666666666666666666666666666666666666666666666666666666",
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Extra field is ignored
    let invalid_json = r#"{
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "public": "5866666666666666666666666666666666666666666666666666666666666666",
        "group_public": "5866666666666666666666666666666666666666666666666666666666666666",
        "extra_field": 1,
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_ok());
}

#[test]
fn check_public_key_package_serialization() {
    let public_key_package = samples::public_key_package();

    let json = serde_json::to_string_pretty(&public_key_package).unwrap();
    println!("{}", json);

    let decoded_public_key_package: PublicKeyPackage = serde_json::from_str(&json).unwrap();
    assert!(public_key_package == decoded_public_key_package);

    let json = r#"{
        "signer_pubkeys": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "5866666666666666666666666666666666666666666666666666666666666666"
        },
        "group_public": "5866666666666666666666666666666666666666666666666666666666666666",
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    let decoded_public_key_package: PublicKeyPackage = serde_json::from_str(json).unwrap();
    assert!(public_key_package == decoded_public_key_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "signer_pubkeys": {
          "0000000000000000000000000000000000000000000000000000000000000000": "5866666666666666666666666666666666666666666666666666666666666666"
        },
        "group_public": "5866666666666666666666666666666666666666666666666666666666666666",
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "signer_pubkeys": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "5866666666666666666666666666666666666666666666666666666666666666"
        },
        "foo": "5866666666666666666666666666666666666666666666666666666666666666",
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "signer_pubkeys": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "5866666666666666666666666666666666666666666666666666666666666666"
        },
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Extra field is ignored
    let invalid_json = r#"{
        "signer_pubkeys": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "5866666666666666666666666666666666666666666666666666666666666666"
        },
        "group_public": "5866666666666666666666666666666666666666666666666666666666666666",
        "extra": 1,
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_ok());
}

#[test]
fn check_round1_package_serialization() {
    let round1_package = samples::round1_package();

    let json = serde_json::to_string_pretty(&round1_package).unwrap();
    println!("{}", json);

    let decoded_round1_package: round1::Package = serde_json::from_str(&json).unwrap();
    assert!(round1_package == decoded_round1_package);

    let json = r#"{
        "commitment": [
          "5866666666666666666666666666666666666666666666666666666666666666"
        ],
        "proof_of_knowledge": "5866666666666666666666666666666666666666666666666666666666666666498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    let decoded_round1_package: round1::Package = serde_json::from_str(json).unwrap();
    assert!(round1_package == decoded_round1_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "commitment": [
          "5866666666666666666666666666666666666666666666666666666666666666"
        ],
        "foo": "5866666666666666666666666666666666666666666666666666666666666666498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "commitment": [
          "5866666666666666666666666666666666666666666666666666666666666666"
        ],
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Extra field is ignored
    let invalid_json = r#"{
        "commitment": [
          "5866666666666666666666666666666666666666666666666666666666666666"
        ],
        "proof_of_knowledge": "5866666666666666666666666666666666666666666666666666666666666666498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "extra": 1,
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_ok());
}

#[test]
fn check_round2_package_serialization() {
    let round2_package = samples::round2_package();

    let json = serde_json::to_string_pretty(&round2_package).unwrap();
    println!("{}", json);

    let decoded_round2_package: round2::Package = serde_json::from_str(&json).unwrap();
    assert!(round2_package == decoded_round2_package);

    let json = r#"{
        "secret_share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    let decoded_round2_package: round2::Package = serde_json::from_str(json).unwrap();
    assert!(round2_package == decoded_round2_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "foo": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Extra field is ignored
    let invalid_json = r#"{
        "secret_share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "extra": 1,
        "ciphersuite": "FROST(Ed25519, SHA-512)"
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_ok());
}
