#![cfg(feature = "serde")]

mod helpers;

use frost_ed448::{
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
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "hiding": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        "binding": "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80"
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
      "hiding": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
      "binding": "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80"
    }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "foo": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        "binding": "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80"
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "foo": "0000000000000000000000000000000000000000000000000000000000000000",
        "binding": "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80"
      }"#;
    assert!(serde_json::from_str::<SigningCommitments>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST(Ed25519, SHA-512)"
        },
        "hiding": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        "binding": "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80",
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
        "ciphersuite": "FROST-ED448-SHAKE256-v1"
      },
      "signing_commitments": {
        "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": {
          "header": {
            "version": 0,
            "ciphersuite": "FROST-ED448-SHAKE256-v1"
          },
          "hiding": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
          "binding": "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80"
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
        "ciphersuite": "FROST-ED448-SHAKE256-v1"
      },
      "signing_commitments": {
        "0000000000000000000000000000000000000000000000000000000000000000": {
          "header": {
            "version": 0,
            "ciphersuite": "FROST-ED448-SHAKE256-v1"
          },
          "hiding": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
          "binding": "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80"
        }
      },
      "message": "68656c6c6f20776f726c64"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
      "header": {
        "version": 0,
        "ciphersuite": "FROST-ED448-SHAKE256-v1"
      },
      "signing_commitments": {
        "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": {
          "header": {
            "version": 0,
            "ciphersuite": "FROST-ED448-SHAKE256-v1"
          },
          "foo": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
          "binding": "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80"
        }
      },
      "message": "68656c6c6f20776f726c64"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
      "header": {
        "version": 0,
        "ciphersuite": "FROST-ED448-SHAKE256-v1"
      },
      "signing_commitments": {
        "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": {
          "header": {
            "version": 0,
            "ciphersuite": "FROST-ED448-SHAKE256-v1"
          },
          "binding": "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80"
        }
      },
      "message": "68656c6c6f20776f726c64"
    }"#;
    assert!(serde_json::from_str::<SigningPackage>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
      "header": {
        "version": 0,
        "ciphersuite": "FROST-ED448-SHAKE256-v1"
      },
      "signing_commitments": {
        "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": {
          "header": {
            "version": 0,
            "ciphersuite": "FROST-ED448-SHAKE256-v1"
          },
          "hiding": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
          "binding": "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae80"
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
        "ciphersuite": "FROST-ED448-SHAKE256-v1"
      },
      "share": "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00"
    }"#;
    let decoded_commitments: SignatureShare = serde_json::from_str(json).unwrap();
    assert!(signature_share == decoded_commitments);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "foo": "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00"
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        }
      }"#;
    assert!(serde_json::from_str::<SignatureShare>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "share": "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
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
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "identifier": "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "signing_share": "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        "commitment": [
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
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
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "signing_share": "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        "commitment": [
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
        ]
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "identifier": "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "foo": "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        "commitment": [
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
        ]
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "identifier": "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "commitment": [
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
        ]
      }"#;
    assert!(serde_json::from_str::<SecretShare>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "identifier": "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "signing_share": "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        "commitment": [
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
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
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "identifier": "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "signing_share": "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        "verifying_share": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        "verifying_key": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
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
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "identifier": "0000000000000000000000000000000000000000000000000000000000000000",
        "signing_share": "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        "verifying_share": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        "verifying_key": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        "min_signers": 2
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "identifier": "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "foo": "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        "verifying_share": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        "verifying_key": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "identifier": "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "verifying_share": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        "verifying_key": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "identifier": "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "signing_share": "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        "verifying_share": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        "verifying_key": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        "extra_field": 1
      }"#;
    assert!(serde_json::from_str::<KeyPackage>(invalid_json).is_err());

    // Invalid version
    let invalid_json = r#"{
        "header": {
          "version": 1,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "identifier": "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "secret_share": "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        "public": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
        "group_public": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
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
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "verifying_shares": {
          "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
        },
        "verifying_key": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
      }"#;
    let decoded_public_key_package: PublicKeyPackage = serde_json::from_str(json).unwrap();
    assert!(public_key_package == decoded_public_key_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Invalid identifier
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "verifying_shares": {
          "0000000000000000000000000000000000000000000000000000000000000000": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
        },
        "verifying_key": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "verifying_shares": {
          "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
        },
        "foo": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "verifying_shares": {
          "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
        }
      }"#;
    assert!(serde_json::from_str::<PublicKeyPackage>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "verifying_shares": {
          "2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
        },
        "verifying_key": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
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
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "commitment": [
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
        ],
        "proof_of_knowledge": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f69004d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00"
      }"#;
    let decoded_round1_package: round1::Package = serde_json::from_str(json).unwrap();
    assert!(round1_package == decoded_round1_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "commitment": [
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
        ],
        "foo": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f69004d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00"
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "commitment": [
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
        ]
      }"#;
    assert!(serde_json::from_str::<round1::Package>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "commitment": [
          "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
        ],
        "proof_of_knowledge": "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f69004d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
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
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "signing_share": "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00"
      }"#;
    let decoded_round2_package: round2::Package = serde_json::from_str(json).unwrap();
    assert!(round2_package == decoded_round2_package);

    let invalid_json = "{}";
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Invalid field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "foo": "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00"
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Missing field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        }
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());

    // Extra field
    let invalid_json = r#"{
        "header": {
          "version": 0,
          "ciphersuite": "FROST-ED448-SHAKE256-v1"
        },
        "signing_share": "4d83e51cb78150c2380ad9b3a18148166024e4c9db3cdf82466d3153aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a00",
        "extra": 1
      }"#;
    assert!(serde_json::from_str::<round2::Package>(invalid_json).is_err());
}
