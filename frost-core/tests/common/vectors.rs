use std::{collections::HashMap, str::FromStr};

use curve25519_dalek::scalar::Scalar;
use hex::{self, FromHex};
use lazy_static::lazy_static;
use serde_json::Value;

use frost_core::{
    frost::{keys::*, round1::*, round2::*, *},
    VerifyingKey,
};

use super::ciphersuite::Ristretto255Sha512;

lazy_static! {
    pub static ref RISTRETTO255_SHA512: Value =
        serde_json::from_str(include_str!("vectors.json").trim())
            .expect("Test vector is valid JSON");
}

#[allow(clippy::type_complexity)]
#[allow(dead_code)]
pub(crate) fn parse_test_vectors() -> (
    VerifyingKey<Ristretto255Sha512>,
    HashMap<u16, KeyPackage<Ristretto255Sha512>>,
    &'static str,
    Vec<u8>,
    HashMap<u16, SigningNonces<Ristretto255Sha512>>,
    HashMap<u16, SigningCommitments<Ristretto255Sha512>>,
    Vec<u8>,
    Rho<Ristretto255Sha512>,
    HashMap<u16, SignatureShare<Ristretto255Sha512>>,
    Vec<u8>, // Signature<Ristretto255Sha512>,
) {
    type R = Ristretto255Sha512;

    let inputs = &RISTRETTO255_SHA512["inputs"];

    let message = inputs["message"].as_str().unwrap();
    let message_bytes = hex::decode(message).unwrap();

    let mut key_packages: HashMap<u16, KeyPackage<R>> = HashMap::new();

    let possible_signers = RISTRETTO255_SHA512["inputs"]["signers"]
        .as_object()
        .unwrap()
        .iter();

    let group_public =
        VerifyingKey::<R>::from_hex(inputs["group_public_key"].as_str().unwrap()).unwrap();

    for (i, secret_share) in possible_signers {
        let secret = Secret::<R>::from_hex(secret_share["signer_share"].as_str().unwrap()).unwrap();
        let signer_public = secret.into();

        let key_package = KeyPackage::<R> {
            index: u16::from_str(i).unwrap(),
            secret_share: secret,
            public: signer_public,
            group_public,
        };

        key_packages.insert(*key_package.index(), key_package);
    }

    // Round one outputs

    let round_one_outputs = &RISTRETTO255_SHA512["round_one_outputs"];

    let group_binding_factor_input = Vec::<u8>::from_hex(
        round_one_outputs["group_binding_factor_input"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let group_binding_factor =
        Rho::<R>::from_hex(round_one_outputs["group_binding_factor"].as_str().unwrap()).unwrap();

    let mut signer_nonces: HashMap<u16, SigningNonces<R>> = HashMap::new();
    let mut signer_commitments: HashMap<u16, SigningCommitments<R>> = HashMap::new();

    for (i, signer) in round_one_outputs["signers"].as_object().unwrap().iter() {
        let index = u16::from_str(i).unwrap();

        let signing_nonces = SigningNonces::<R> {
            hiding: Nonce::<R>::from_hex(signer["hiding_nonce"].as_str().unwrap()).unwrap(),
            binding: Nonce::<R>::from_hex(signer["binding_nonce"].as_str().unwrap()).unwrap(),
        };

        signer_nonces.insert(index, signing_nonces);

        let signing_commitments = SigningCommitments::<R> {
            index,
            hiding: NonceCommitment::from_hex(signer["hiding_nonce_commitment"].as_str().unwrap())
                .unwrap(),
            binding: NonceCommitment::from_hex(
                signer["binding_nonce_commitment"].as_str().unwrap(),
            )
            .unwrap(),
        };

        signer_commitments.insert(index, signing_commitments);
    }

    // Round two outputs

    let round_two_outputs = &RISTRETTO255_SHA512["round_two_outputs"];

    let mut signature_shares: HashMap<u16, SignatureShare<R>> = HashMap::new();

    for (i, signer) in round_two_outputs["signers"].as_object().unwrap().iter() {
        let signature_share = SignatureShare::<R> {
            index: u16::from_str(i).unwrap(),
            signature: SignatureResponse {
                z_share: Scalar::from_canonical_bytes(
                    hex::decode(signer["sig_share"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            },
        };

        signature_shares.insert(u16::from_str(i).unwrap(), signature_share);
    }

    // Final output

    let final_output = &RISTRETTO255_SHA512["final_output"];

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
