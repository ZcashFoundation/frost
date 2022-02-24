use std::collections::HashMap;
use std::str::FromStr;

use hex;
use lazy_static::lazy_static;
use serde_json::Value;

use crate::{frost::*, Signature};

lazy_static! {
    pub static ref RISTRETTO255_SHA512: Value =
        serde_json::from_str(include_str!("vectors.json").trim())
            .expect("Test vector is valid JSON");
}

#[allow(clippy::type_complexity)]
pub(crate) fn parse_test_vectors() -> (
    VerificationKey,
    HashMap<u16, KeyPackage>,
    &'static str,
    Vec<u8>,
    HashMap<u16, SigningNonces>,
    HashMap<u16, SigningCommitments>,
    Vec<u8>,
    Rho,
    HashMap<u16, SignatureShare>,
    Signature,
) {
    let inputs = &RISTRETTO255_SHA512["inputs"];

    let message = inputs["message"].as_str().unwrap();
    let message_bytes = hex::decode(message).unwrap();

    let mut key_packages: HashMap<u16, KeyPackage> = HashMap::new();

    let possible_signers = RISTRETTO255_SHA512["inputs"]["signers"]
        .as_object()
        .unwrap()
        .iter();

    let group_public =
        VerificationKey::from_hex(inputs["group_public_key"].as_str().unwrap()).unwrap();

    for (i, secret_share) in possible_signers {
        let secret = Secret::from_hex(secret_share["signer_share"].as_str().unwrap()).unwrap();
        let signer_public = secret.into();

        let key_package = KeyPackage {
            index: u16::from_str(i).unwrap(),
            secret_share: secret,
            public: signer_public,
            group_public,
        };

        key_packages.insert(key_package.index, key_package);
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
        Rho::from_hex(round_one_outputs["group_binding_factor"].as_str().unwrap()).unwrap();

    let mut signer_nonces: HashMap<u16, SigningNonces> = HashMap::new();
    let mut signer_commitments: HashMap<u16, SigningCommitments> = HashMap::new();

    for (i, signer) in round_one_outputs["signers"].as_object().unwrap().iter() {
        let index = u16::from_str(i).unwrap();

        let signing_nonces = SigningNonces {
            hiding: Nonce::from_hex(signer["hiding_nonce"].as_str().unwrap()).unwrap(),
            binding: Nonce::from_hex(signer["binding_nonce"].as_str().unwrap()).unwrap(),
        };

        signer_nonces.insert(index, signing_nonces);

        let signing_commitments = SigningCommitments {
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

    let mut signature_shares: HashMap<u16, SignatureShare> = HashMap::new();

    for (i, signer) in round_two_outputs["signers"].as_object().unwrap().iter() {
        let signature_share = SignatureShare {
            index: u16::from_str(i).unwrap(),
            signature: SignatureResponse {
                R_share: ristretto::CompressedRistretto::from_slice(
                    &hex::decode(signer["group_commitment_share"].as_str().unwrap()).unwrap()[..],
                )
                .decompress()
                .unwrap(),
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

    let signature = Signature::from_hex(final_output["sig"].as_str().unwrap()).unwrap();

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
        signature,
    )
}
