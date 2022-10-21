//! Helper function for testing with test vectors.
use std::{collections::HashMap, str::FromStr};

use debugless_unwrap::DebuglessUnwrap;
use hex::{self, FromHex};
use serde_json::Value;

use crate::{
    frost::{self, keys::*, round1::*, round2::*, *},
    Ciphersuite, Field, Group, Scalar, VerifyingKey,
};

/// Parse test vectors for a given ciphersuite.
#[allow(clippy::type_complexity)]
pub fn parse_test_vectors<C: Ciphersuite>(
    json_vectors: &Value,
) -> (
    SharedSecret<C>,
    VerifyingKey<C>,
    HashMap<Identifier<C>, KeyPackage<C>>,
    Vec<u8>,
    Vec<Scalar<C>>,
    HashMap<Identifier<C>, SigningNonces<C>>,
    HashMap<Identifier<C>, SigningCommitments<C>>,
    HashMap<Identifier<C>, Vec<u8>>,
    HashMap<Identifier<C>, BindingFactor<C>>,
    HashMap<Identifier<C>, SignatureShare<C>>,
    Vec<u8>, // Signature<C>,
) {
    let inputs = &json_vectors["inputs"];

    let secret_key_str = inputs["group_secret_key"].as_str().unwrap();
    let secret_key_bytes = hex::decode(secret_key_str).unwrap();
    let secret_key =
        SharedSecret::from_bytes(secret_key_bytes.try_into().debugless_unwrap()).unwrap();

    let message = inputs["message"].as_str().unwrap();
    let message_bytes = hex::decode(message).unwrap();

    let share_polynomial_coefficients = inputs["share_polynomial_coefficients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let vec = hex::decode(v.as_str().unwrap()).unwrap();
            <<C::Group as Group>::Field as Field>::deserialize(&vec.try_into().debugless_unwrap())
                .unwrap()
        })
        .collect();

    let mut key_packages: HashMap<Identifier<C>, KeyPackage<C>> = HashMap::new();

    let possible_participants = json_vectors["inputs"]["participants"]
        .as_object()
        .unwrap()
        .iter();

    let group_public =
        VerifyingKey::<C>::from_hex(inputs["group_public_key"].as_str().unwrap()).unwrap();

    for (i, secret_share) in possible_participants {
        let secret =
            SigningShare::<C>::from_hex(secret_share["participant_share"].as_str().unwrap())
                .unwrap();
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

    let mut signer_nonces: HashMap<Identifier<C>, SigningNonces<C>> = HashMap::new();
    let mut signer_commitments: HashMap<Identifier<C>, SigningCommitments<C>> = HashMap::new();
    let mut binding_factor_inputs: HashMap<Identifier<C>, Vec<u8>> = HashMap::new();
    let mut binding_factors: HashMap<Identifier<C>, BindingFactor<C>> = HashMap::new();

    for (i, signer) in round_one_outputs["participants"]
        .as_object()
        .unwrap()
        .iter()
    {
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

        let binding_factor_input =
            Vec::<u8>::from_hex(signer["binding_factor_input"].as_str().unwrap()).unwrap();

        binding_factor_inputs.insert(identifier, binding_factor_input);

        let binding_factor =
            BindingFactor::<C>::from_hex(signer["binding_factor"].as_str().unwrap()).unwrap();

        binding_factors.insert(identifier, binding_factor);
    }

    // Round two outputs

    let round_two_outputs = &json_vectors["round_two_outputs"];

    let mut signature_shares: HashMap<Identifier<C>, SignatureShare<C>> = HashMap::new();

    for (i, signer) in round_two_outputs["participants"]
        .as_object()
        .unwrap()
        .iter()
    {
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
        secret_key,
        group_public,
        key_packages,
        message_bytes,
        share_polynomial_coefficients,
        signer_nonces,
        signer_commitments,
        binding_factor_inputs,
        binding_factors,
        signature_shares,
        signature_bytes,
    )
}

/// Test with the given test vectors for a ciphersuite.
pub fn check_sign_with_test_vectors<C: Ciphersuite>(json_vectors: &Value) {
    let (
        secret_key,
        group_public,
        key_packages,
        message_bytes,
        share_polynomials_coefficients,
        signer_nonces,
        signer_commitments,
        binding_factor_inputs,
        binding_factors,
        signature_shares,
        signature_bytes,
    ) = parse_test_vectors(json_vectors);

    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let numshares = key_packages.len();
    let threshold = share_polynomials_coefficients.len() + 1;
    let secret_shares = generate_secret_shares(
        &secret_key,
        numshares as u8,
        threshold as u8,
        share_polynomials_coefficients,
    )
    .unwrap();
    let secret_shares: HashMap<_, _> = secret_shares
        .iter()
        .map(|share| (share.identifier, share))
        .collect();

    for key_package in key_packages.values() {
        assert_eq!(
            *key_package.public(),
            frost::keys::VerifyingShare::from(*key_package.secret_share())
        );
        assert_eq!(
            key_package.secret_share(),
            secret_shares[key_package.identifier()].secret()
        )
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

    for (identifier, input) in signing_package.binding_factor_preimages().iter() {
        assert_eq!(*input, binding_factor_inputs[identifier]);
    }

    let binding_factor_list: frost::BindingFactorList<C> = (&signing_package).into();

    for (identifier, binding_factor) in binding_factor_list.iter() {
        assert_eq!(*binding_factor, binding_factors[identifier]);
    }

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
