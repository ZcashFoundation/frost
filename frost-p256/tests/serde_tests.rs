#![cfg(feature = "serde")]

mod helpers;

use frost_p256::{
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
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "hiding": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "binding": "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
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
      "hiding": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      "binding": "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
    }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "foo": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "binding": "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "foo": "0000000000000000000000000000000000000000000000000000000000000000",
        "binding": "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST(Ed25519, SHA-512)"
        },
        "hiding": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "binding": "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
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
        "ciphersuite": "FROST-P256-SHA256-v1"
      },
      "signing_commitments": {
        "000000000000000000000000000000000000000000000000000000000000002a": {
          "header": {
            "version": 0,
            "ciphersuite": "FROST-P256-SHA256-v1"
          },
          "hiding": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
          "binding": "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
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
        "ciphersuite": "FROST-P256-SHA256-v1"
      },
      "signing_commitments": {
        "0000000000000000000000000000000000000000000000000000000000000000": {
          "header": {
            "version": 0,
            "ciphersuite": "FROST-P256-SHA256-v1"
          },
          "hiding": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
          "binding": "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
        }
      },
      "message": "68656c6c6f20776f726c64"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
      "header": {
        "version": 0,
        "ciphersuite": "FROST-P256-SHA256-v1"
      },
      "signing_commitments": {
        "000000000000000000000000000000000000000000000000000000000000002a": {
          "header": {
            "version": 0,
            "ciphersuite": "FROST-P256-SHA256-v1"
          },
          "foo": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
          "binding": "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
        }
      },
      "message": "68656c6c6f20776f726c64"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
      "header": {
        "version": 0,
        "ciphersuite": "FROST-P256-SHA256-v1"
      },
      "signing_commitments": {
        "000000000000000000000000000000000000000000000000000000000000002a": {
          "header": {
            "version": 0,
            "ciphersuite": "FROST-P256-SHA256-v1"
          },
          "binding": "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
        }
      },
      "message": "68656c6c6f20776f726c64"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
      "header": {
        "version": 0,
        "ciphersuite": "FROST-P256-SHA256-v1"
      },
      "signing_commitments": {
        "000000000000000000000000000000000000000000000000000000000000002a": {
          "header": {
            "version": 0,
            "ciphersuite": "FROST-P256-SHA256-v1"
          },
          "hiding": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
          "binding": "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
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
        "ciphersuite": "FROST-P256-SHA256-v1"
      },
      "share": "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1"
    }"#;
    let decoded_commitments: SignatureShare = serde_json::from_str(json).unwrap();
    assert!(signature_share == decoded_commitments);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "foo": "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1"
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        }
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "share": "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
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
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "identifier": "000000000000000000000000000000000000000000000000000000000000002a",
        "signing_share": "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        "commitment": [
          "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
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
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "signing_share": "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        "commitment": [
          "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        ]
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "identifier": "000000000000000000000000000000000000000000000000000000000000002a",
        "foo": "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        "commitment": [
          "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        ]
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "identifier": "000000000000000000000000000000000000000000000000000000000000002a",
        "commitment": [
          "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        ]
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "identifier": "000000000000000000000000000000000000000000000000000000000000002a",
        "signing_share": "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        "commitment": [
          "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
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
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "identifier": "000000000000000000000000000000000000000000000000000000000000002a",
        "signing_share": "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        "verifying_share": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "verifying_key": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
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
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "signing_share": "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        "verifying_share": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "verifying_key": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "min_signers": 2
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "identifier": "000000000000000000000000000000000000000000000000000000000000002a",
        "foo": "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        "verifying_share": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "verifying_key": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "identifier": "000000000000000000000000000000000000000000000000000000000000002a",
        "verifying_share": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "verifying_key": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "identifier": "000000000000000000000000000000000000000000000000000000000000002a",
        "signing_share": "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        "verifying_share": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "verifying_key": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "extra_field": 1
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Invalid version
    let invalid_json = r#"{
        "header": {
          "version": 1,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "identifier": "000000000000000000000000000000000000000000000000000000000000002a",
        "secret_share": "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        "public": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "group_public": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
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
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "verifying_shares": {
          "000000000000000000000000000000000000000000000000000000000000002a": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        },
        "verifying_key": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
      }"#;
    let decoded_public_key_package: PublicKeyPackage = serde_json::from_str(json).unwrap();
    assert!(public_key_package == decoded_public_key_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "verifying_shares": {
          "0000000000000000000000000000000000000000000000000000000000000000": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        },
        "verifying_key": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "verifying_shares": {
          "000000000000000000000000000000000000000000000000000000000000002a": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        },
        "foo": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "verifying_shares": {
          "000000000000000000000000000000000000000000000000000000000000002a": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        }
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "verifying_shares": {
          "000000000000000000000000000000000000000000000000000000000000002a": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        },
        "verifying_key": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
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
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "commitment": [
          "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        ],
        "proof_of_knowledge": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1"
      }"#;
    let decoded_round1_package: round1::Package = serde_json::from_str(json).unwrap();
    assert!(round1_package == decoded_round1_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "commitment": [
          "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        ],
        "foo": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1"
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "commitment": [
          "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        ]
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "commitment": [
          "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        ],
        "proof_of_knowledge": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
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
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "signing_share": "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1"
      }"#;
    let decoded_round2_package: round2::Package = serde_json::from_str(json).unwrap();
    assert!(round2_package == decoded_round2_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "foo": "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1"
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        }
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-P256-SHA256-v1"
        },
        "signing_share": "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
        "extra": 1
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());
}
