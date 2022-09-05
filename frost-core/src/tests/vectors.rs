//! Helper function for testing with test vectors.
use std::{collections::HashMap, str::FromStr};

use debugless_unwrap::DebuglessUnwrap;
use hex::{self, FromHex};
use serde_json::Value;

use crate::{
    frost::{self, keys::*, round1::*, round2::*, *},
    Ciphersuite, Field, Group, VerifyingKey,
};

/// Parse test vectors for a given ciphersuite.
#[allow(clippy::type_complexity)]
pub fn parse_test_vectors<C: Ciphersuite>(
    json_vectors: &Value,
) -> (
    VerifyingKey<C>,
    HashMap<Identifier<C>, KeyPackage<C>>,
    Vec<u8>,
    HashMap<Identifier<C>, SigningNonces<C>>,
    HashMap<Identifier<C>, SigningCommitments<C>>,
    Vec<u8>,
    Rho<C>,
    HashMap<Identifier<C>, SignatureShare<C>>,
    Vec<u8>, // Signature<C>,
) {
    let inputs = &json_vectors["inputs"];

    let message = inputs["message"].as_str().unwrap();
    let message_bytes = hex::decode(message).unwrap();

    let mut key_packages: HashMap<Identifier<C>, KeyPackage<C>> = HashMap::new();

    let possible_signers = json_vectors["inputs"]["signers"]
        .as_object()
        .unwrap()
        .iter();

    let group_public =
        VerifyingKey::<C>::from_hex(inputs["group_public_key"].as_str().unwrap()).unwrap();

    for (i, secret_share) in possible_signers {
        let secret = Secret::<C>::from_hex(secret_share["signer_share"].as_str().unwrap()).unwrap();
        let signer_public = secret.into();

        let key_package = KeyPackage::<C> {
            identifier: u16::from_str(i).unwrap().try_into().unwrap(),
            secret_share: secret,
            public: signer_public,
            group_public,
        };

        key_packages.insert(*key_package.identifier(), key_package);
    }

    // Round one outputs

    let round_one_outputs = &json_vectors["round_one_outputs"];

    let group_binding_factor_input = Vec::<u8>::from_hex(
        round_one_outputs["group_binding_factor_input"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let group_binding_factor =
        Rho::<C>::from_hex(round_one_outputs["group_binding_factor"].as_str().unwrap()).unwrap();

    let mut signer_nonces: HashMap<Identifier<C>, SigningNonces<C>> = HashMap::new();
    let mut signer_commitments: HashMap<Identifier<C>, SigningCommitments<C>> = HashMap::new();

    for (i, signer) in round_one_outputs["signers"].as_object().unwrap().iter() {
        let identifier = u16::from_str(i).unwrap().try_into().unwrap();

        let signing_nonces = SigningNonces::<C> {
            hiding: Nonce::<C>::from_hex(signer["hiding_nonce"].as_str().unwrap()).unwrap(),
            binding: Nonce::<C>::from_hex(signer["binding_nonce"].as_str().unwrap()).unwrap(),
        };

        signer_nonces.insert(identifier, signing_nonces);

        let signing_commitments = SigningCommitments::<C> {
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

    let round_two_outputs = &json_vectors["round_two_outputs"];

    let mut signature_shares: HashMap<Identifier<C>, SignatureShare<C>> = HashMap::new();

    for (i, signer) in round_two_outputs["signers"].as_object().unwrap().iter() {
        let sig_share = <<C::Group as Group>::Field as Field>::Serialization::try_from(
            hex::decode(signer["sig_share"].as_str().unwrap()).unwrap(),
        )
        .debugless_unwrap();

        let signature_share = SignatureShare::<C> {
            identifier: u16::from_str(i).unwrap().try_into().unwrap(),
            signature: SignatureResponse {
                z_share: <<C::Group as Group>::Field as Field>::deserialize(&sig_share).unwrap(),
            },
        };

        signature_shares.insert(
            u16::from_str(i).unwrap().try_into().unwrap(),
            signature_share,
        );
    }

    // Final output

    let final_output = &json_vectors["final_output"];

    let signature_bytes = FromHex::from_hex(final_output["sig"].as_str().unwrap()).unwrap();

    (
        group_public,
        key_packages,
        message_bytes,
        signer_nonces,
        signer_commitments,
        group_binding_factor_input,
        group_binding_factor,
        signature_shares,
        signature_bytes,
    )
}

/// Test with the given test vectors for a ciphersuite.
pub fn check_sign_with_test_vectors<C: Ciphersuite + PartialEq>(json_vectors: &Value)
where
    C::Group: PartialEq,
{
    let (
        group_public,
        key_packages,
        message_bytes,
        signer_nonces,
        signer_commitments,
        group_binding_factor_input,
        group_binding_factor,
        signature_shares,
        signature_bytes,
    ) = parse_test_vectors(json_vectors);

    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    for key_package in key_packages.values() {
        assert_eq!(
            *key_package.public(),
            frost::keys::Public::from(*key_package.secret_share())
        );
    }

    /////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    /////////////////////////////////////////////////////////////////////////////

    for (i, _) in signer_commitments.clone() {
        // compute nonce commitments from nonces
        let nonces = signer_nonces.get(&i).unwrap();
        let nonce_commitments = signer_commitments.get(&i).unwrap();

        assert_eq!(
            &frost::round1::NonceCommitment::from(nonces.hiding()),
            nonce_commitments.hiding()
        );

        assert_eq!(
            &frost::round1::NonceCommitment::from(nonces.binding()),
            nonce_commitments.binding()
        );
    }

    /////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    /////////////////////////////////////////////////////////////////////////////

    let signer_commitments_vec = signer_commitments
        .into_iter()
        .map(|(_, signing_commitments)| signing_commitments)
        .collect();

    let signing_package = frost::SigningPackage::new(signer_commitments_vec, message_bytes);

    assert_eq!(signing_package.rho_preimage(), group_binding_factor_input);

    let rho: frost::Rho<C> = (&signing_package).into();

    assert_eq!(rho, group_binding_factor);

    let mut our_signature_shares: Vec<frost::round2::SignatureShare<C>> = Vec::new();

    // Each participant generates their signature share
    for identifier in signer_nonces.keys() {
        let key_package = &key_packages[identifier];
        let nonces = &signer_nonces[identifier];

        // Each participant generates their signature share.
        let signature_share = frost::round2::sign(&signing_package, nonces, key_package).unwrap();

        our_signature_shares.push(signature_share);
    }

    for sig_share in our_signature_shares.clone() {
        assert_eq!(sig_share, signature_shares[sig_share.identifier()]);
    }

    let signer_pubkeys = key_packages
        .into_iter()
        .map(|(i, key_package)| (i, *key_package.public()))
        .collect();

    let pubkey_package = frost::keys::PublicKeyPackage {
        signer_pubkeys,
        group_public,
    };

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation:  collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate the FROST signature from test vector sig shares
    let group_signature_result = frost::aggregate(
        &signing_package,
        &signature_shares
            .values()
            .cloned()
            .collect::<Vec<frost::round2::SignatureShare<C>>>(),
        &pubkey_package,
    );

    // Check that the aggregation passed signature share verification and generation
    assert!(group_signature_result.is_ok());

    // Check that the generated signature matches the test vector signature
    let group_signature = group_signature_result.unwrap();
    assert_eq!(group_signature.to_bytes().as_ref(), signature_bytes);

    // Aggregate the FROST signature from our signature shares
    let group_signature_result =
        frost::aggregate(&signing_package, &our_signature_shares, &pubkey_package);

    // Check that the aggregation passed signature share verification and generation
    assert!(group_signature_result.is_ok());

    // Check that the generated signature matches the test vector signature
    let group_signature = group_signature_result.unwrap();
    assert_eq!(group_signature.to_bytes().as_ref(), signature_bytes);
}
