#![cfg(feature = "serde")]

mod helpers;

use frost_ristretto255::{
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
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "hiding": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"
      }"#;
    let decoded_commitments: SigningCommitments = serde_json::from_str(json).unwrap();
    assert!(commitments == decoded_commitments);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Wrong ciphersuite
    let invalid_json = r#"{
      "header": {
        "version": 0,
        "ciphersuite": "FROST(Wrong, SHA-512)"
      },
      "hiding": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
      "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"
    }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "foo": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "foo": "0000000000000000000000000000000000000000000000000000000000000000",
        "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST(Ed25519, SHA-512)"
        },
        "hiding": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
        "extra": 1
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());
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
      "header": {
        "version": 0,
        "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
      },
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "header": {
            "version": 0,
            "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
          },
          "hiding": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
          "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"
        }
      },
      "message": "68656c6c6f20776f726c64"
    }"#;
    let decoded_signing_package: SigningPackage = serde_json::from_str(json).unwrap();
    assert!(signing_package == decoded_signing_package);

    // Invalid identifier
    let invalid_json = r#"{
      "header": {
        "version": 0,
        "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
      },
      "signing_commitments": {
        "0000000000000000000000000000000000000000000000000000000000000000": {
          "header": {
            "version": 0,
            "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
          },
          "hiding": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
          "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"
        }
      },
      "message": "68656c6c6f20776f726c64"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
      "header": {
        "version": 0,
        "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
      },
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "header": {
            "version": 0,
            "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
          },
          "foo": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
          "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"
        }
      },
      "message": "68656c6c6f20776f726c64"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
      "header": {
        "version": 0,
        "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
      },
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "header": {
            "version": 0,
            "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
          },
          "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"
        }
      },
      "message": "68656c6c6f20776f726c64"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
      "header": {
        "version": 0,
        "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
      },
      "signing_commitments": {
        "2a00000000000000000000000000000000000000000000000000000000000000": {
          "header": {
            "version": 0,
            "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
          },
          "hiding": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
          "binding": "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"
        }
      },
      "message": "68656c6c6f20776f726c64",
      "extra": 1
    }
    "#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());
}

#[test]
fn check_signature_share_serialization() {
    let signature_share = samples::signature_share();

    let json = serde_json::to_string_pretty(&signature_share).unwrap();
    println!("{}", json);

    let decoded_signature_share: SignatureShare = serde_json::from_str(&json).unwrap();
    assert!(signature_share == decoded_signature_share);

    let json = r#"{
      "header": {
        "version": 0,
        "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
      },
      "share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a"
    }"#;
    let decoded_commitments: SignatureShare = serde_json::from_str(json).unwrap();
    assert!(signature_share == decoded_commitments);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "foo": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a"
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        }
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "extra": 1
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());
}

#[test]
fn check_secret_share_serialization() {
    let secret_share = samples::secret_share();

    let json = serde_json::to_string_pretty(&secret_share).unwrap();
    println!("{}", json);

    let decoded_secret_share: SecretShare = serde_json::from_str(&json).unwrap();
    assert!(secret_share == decoded_secret_share);

    let json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "signing_share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ]
      }"#;
    let decoded_secret_share: SecretShare = serde_json::from_str(json).unwrap();
    assert!(secret_share == decoded_secret_share);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "signing_share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ]
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "foo": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ]
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ]
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "signing_share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ]
        "extra": 1,
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());
}

#[test]
fn check_key_package_serialization() {
    let key_package = samples::key_package();

    let json = serde_json::to_string_pretty(&key_package).unwrap();
    println!("{}", json);

    let decoded_key_package: KeyPackage = serde_json::from_str(&json).unwrap();
    assert!(key_package == decoded_key_package);

    let json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "signing_share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "verifying_share": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "verifying_key": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "min_signers": 2
      }"#;
    let decoded_key_package: KeyPackage = serde_json::from_str(json).unwrap();
    assert!(key_package == decoded_key_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "signing_share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "verifying_share": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "verifying_key": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "min_signers": 2
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "foo": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "verifying_share": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "verifying_key": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "verifying_share": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "verifying_key": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "signing_share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "verifying_share": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "verifying_key": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "extra_field": 1
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Invalid version
    let invalid_json = r#"{
        "header": {
          "version": 1,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "identifier": "2a00000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "public": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "group_public": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "min_signers": 2
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());
}

#[test]
fn check_public_key_package_serialization() {
    let public_key_package = samples::public_key_package();

    let json = serde_json::to_string_pretty(&public_key_package).unwrap();
    println!("{}", json);

    let decoded_public_key_package: PublicKeyPackage = serde_json::from_str(&json).unwrap();
    assert!(public_key_package == decoded_public_key_package);

    let json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "verifying_shares": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        },
        "verifying_key": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
      }"#;
    let decoded_public_key_package: PublicKeyPackage = serde_json::from_str(json).unwrap();
    assert!(public_key_package == decoded_public_key_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "verifying_shares": {
          "0000000000000000000000000000000000000000000000000000000000000000": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        },
        "verifying_key": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "verifying_shares": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        },
        "foo": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "verifying_shares": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        }
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "verifying_shares": {
          "2a00000000000000000000000000000000000000000000000000000000000000": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        },
        "verifying_key": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "extra": 1
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());
}

#[test]
fn check_round1_package_serialization() {
    let round1_package = samples::round1_package();

    let json = serde_json::to_string_pretty(&round1_package).unwrap();
    println!("{}", json);

    let decoded_round1_package: round1::Package = serde_json::from_str(&json).unwrap();
    assert!(round1_package == decoded_round1_package);

    let json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ],
        "proof_of_knowledge": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a"
      }"#;
    let decoded_round1_package: round1::Package = serde_json::from_str(json).unwrap();
    assert!(round1_package == decoded_round1_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ],
        "foo": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a"
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ]
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "commitment": [
          "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        ],
        "proof_of_knowledge": "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "extra": 1
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());
}

#[test]
fn check_round2_package_serialization() {
    let round2_package = samples::round2_package();

    let json = serde_json::to_string_pretty(&round2_package).unwrap();
    println!("{}", json);

    let decoded_round2_package: round2::Package = serde_json::from_str(&json).unwrap();
    assert!(round2_package == decoded_round2_package);

    let json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "signing_share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a"
      }"#;
    let decoded_round2_package: round2::Package = serde_json::from_str(json).unwrap();
    assert!(round2_package == decoded_round2_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "foo": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a"
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        }
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-RISTRETTO255-SHA512-v1"
        },
        "signing_share": "498d4e9311420c903913a56c94a694b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a",
        "extra": 1
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());
}
