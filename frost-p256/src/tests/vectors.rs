use std::{collections::HashMap, str::FromStr};

use hex::{self, FromHex};
use lazy_static::lazy_static;
use p256::elliptic_curve::PrimeField;
use p256::{FieldBytes, Scalar};
use serde_json::Value;

use frost_core::{
    frost::{keys::*, round1::*, round2::*, *},
    VerifyingKey,
};

use crate::P256Sha256;

lazy_static! {
    pub static ref P256_SHA256: Value = serde_json::from_str(include_str!("vectors.json").trim())
        .expect("Test vector is valid JSON");
}

#[allow(clippy::type_complexity)]
#[allow(dead_code)]
pub(crate) fn parse_test_vectors() -> (
    VerifyingKey<P256Sha256>,
    HashMap<Identifier<P256Sha256>, KeyPackage<P256Sha256>>,
    &'static str,
    Vec<u8>,
    HashMap<Identifier<P256Sha256>, SigningNonces<P256Sha256>>,
    HashMap<Identifier<P256Sha256>, SigningCommitments<P256Sha256>>,
    Vec<u8>,
    Rho<P256Sha256>,
    HashMap<Identifier<P256Sha256>, SignatureShare<P256Sha256>>,
    Vec<u8>, // Signature<P256Sha256>,
) {
    type R = P256Sha256;

    let inputs = &P256_SHA256["inputs"];

    let message = inputs["message"].as_str().unwrap();
    let message_bytes = hex::decode(message).unwrap();

    let mut key_packages: HashMap<Identifier<P256Sha256>, KeyPackage<R>> = HashMap::new();

    let possible_signers = P256_SHA256["inputs"]["signers"].as_object().unwrap().iter();

    let group_public =
        VerifyingKey::<R>::from_hex(inputs["group_public_key"].as_str().unwrap()).unwrap();

    for (i, secret_share) in possible_signers {
        let secret = Secret::<R>::from_hex(secret_share["signer_share"].as_str().unwrap()).unwrap();
        let signer_public = secret.into();

        let key_package = KeyPackage::<R> {
            identifier: u16::from_str(i).unwrap().try_into().unwrap(),
            secret_share: secret,
            public: signer_public,
            group_public,
        };

        key_packages.insert(*key_package.identifier(), key_package);
    }

    // Round one outputs

    let round_one_outputs = &P256_SHA256["round_one_outputs"];

    let group_binding_factor_input = Vec::<u8>::from_hex(
        round_one_outputs["group_binding_factor_input"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let group_binding_factor =
        Rho::<R>::from_hex(round_one_outputs["group_binding_factor"].as_str().unwrap()).unwrap();

    let mut signer_nonces: HashMap<Identifier<R>, SigningNonces<R>> = HashMap::new();
    let mut signer_commitments: HashMap<Identifier<R>, SigningCommitments<R>> = HashMap::new();

    for (i, signer) in round_one_outputs["signers"].as_object().unwrap().iter() {
        let identifier = u16::from_str(i).unwrap().try_into().unwrap();

        let signing_nonces = SigningNonces::<R> {
            hiding: Nonce::<R>::from_hex(signer["hiding_nonce"].as_str().unwrap()).unwrap(),
            binding: Nonce::<R>::from_hex(signer["binding_nonce"].as_str().unwrap()).unwrap(),
        };

        signer_nonces.insert(identifier, signing_nonces);

        let signing_commitments = SigningCommitments::<R> {
            identifier,
            hiding: NonceCommitment::from_hex(signer["hiding_nonce_commitment"].as_str().unwrap())
                .unwrap(),
            binding: NonceCommitment::from_hex(
                signer["binding_nonce_commitment"].as_str().unwrap(),
            )
            .unwrap(),
        };

        signer_commitments.insert(identifier, signing_commitments);
    }

    // Round two outputs

    let round_two_outputs = &P256_SHA256["round_two_outputs"];

    let mut signature_shares: HashMap<Identifier<R>, SignatureShare<R>> = HashMap::new();

    for (i, signer) in round_two_outputs["signers"].as_object().unwrap().iter() {
        let signature_share = SignatureShare::<R> {
            identifier: u16::from_str(i).unwrap().try_into().unwrap(),
            signature: SignatureResponse {
                z_share: Scalar::from_repr(*FieldBytes::from_slice(
                    hex::decode(signer["sig_share"].as_str().unwrap())
                        .unwrap()
                        .as_slice(),
                ))
                .unwrap(),
            },
        };

        signature_shares.insert(
            u16::from_str(i).unwrap().try_into().unwrap(),
            signature_share,
        );
    }

    // Final output

    let final_output = &P256_SHA256["final_output"];

    let signature_bytes = FromHex::from_hex(final_output["sig"].as_str().unwrap()).unwrap();

    (
        group_public,
        key_packages,
        message,
        message_bytes,
        signer_nonces,
        signer_commitments,
        group_binding_factor_input,
        group_binding_factor,
        signature_shares,
        signature_bytes,
    )
}
