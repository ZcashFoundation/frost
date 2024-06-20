//! Helper function for testing with test vectors.
use alloc::collections::BTreeMap;

use debugless_unwrap::DebuglessUnwrap;
use hex::{self, FromHex};
use serde_json::Value;

use crate as frost;
use crate::{
    keys::*, round1::*, round2::*, Ciphersuite, Field, Group, Scalar, SigningKey, VerifyingKey, *,
};

/// Test vectors for a ciphersuite.
pub struct TestVectors<C: Ciphersuite> {
    secret_key: SigningKey<C>,
    verifying_key: VerifyingKey<C>,
    key_packages: BTreeMap<Identifier<C>, KeyPackage<C>>,
    message_bytes: Vec<u8>,
    share_polynomial_coefficients: Vec<Scalar<C>>,
    hiding_nonces_randomness: BTreeMap<Identifier<C>, Vec<u8>>,
    binding_nonces_randomness: BTreeMap<Identifier<C>, Vec<u8>>,
    signer_nonces: BTreeMap<Identifier<C>, SigningNonces<C>>,
    signer_commitments: BTreeMap<Identifier<C>, SigningCommitments<C>>,
    binding_factor_inputs: BTreeMap<Identifier<C>, Vec<u8>>,
    binding_factors: BTreeMap<Identifier<C>, BindingFactor<C>>,
    signature_shares: BTreeMap<Identifier<C>, SignatureShare<C>>,
    signature_bytes: Vec<u8>,
}

/// Parse test vectors for a given ciphersuite.
#[allow(clippy::type_complexity)]
pub fn parse_test_vectors<C: Ciphersuite>(json_vectors: &Value) -> TestVectors<C> {
    let inputs = &json_vectors["inputs"];

    let secret_key_str = inputs["group_secret_key"].as_str().unwrap();
    let secret_key_bytes = hex::decode(secret_key_str).unwrap();
    let secret_key = SigningKey::deserialize(&secret_key_bytes).unwrap();

    let message = inputs["message"].as_str().unwrap();
    let message_bytes = hex::decode(message).unwrap();

    let share_polynomial_coefficients: Vec<_> = inputs["share_polynomial_coefficients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let vec = hex::decode(v.as_str().unwrap()).unwrap();
            <<C::Group as Group>::Field>::deserialize(&vec.try_into().debugless_unwrap()).unwrap()
        })
        .collect();

    let mut key_packages: BTreeMap<Identifier<C>, KeyPackage<C>> = BTreeMap::new();

    let possible_participants = json_vectors["inputs"].as_object().unwrap()["participant_shares"]
        .as_array()
        .unwrap()
        .iter();

    let verifying_key =
        VerifyingKey::<C>::from_hex(inputs["verifying_key_key"].as_str().unwrap()).unwrap();

    for secret_share in possible_participants {
        let i = secret_share["identifier"].as_u64().unwrap() as u16;
        let secret =
            SigningShare::<C>::from_hex(secret_share["participant_share"].as_str().unwrap())
                .unwrap();
        let signer_public = secret.into();

        let min_signers = share_polynomial_coefficients.len() + 1;
        let key_package = KeyPackage::<C>::new(
            i.try_into().unwrap(),
            secret,
            signer_public,
            verifying_key,
            min_signers as u16,
        );

        key_packages.insert(*key_package.identifier(), key_package);
    }

    // Round one outputs

    let round_one_outputs = &json_vectors["round_one_outputs"];

    let mut hiding_nonces_randomness: BTreeMap<Identifier<C>, Vec<u8>> = BTreeMap::new();
    let mut binding_nonces_randomness: BTreeMap<Identifier<C>, Vec<u8>> = BTreeMap::new();
    let mut signer_nonces: BTreeMap<Identifier<C>, SigningNonces<C>> = BTreeMap::new();
    let mut signer_commitments: BTreeMap<Identifier<C>, SigningCommitments<C>> = BTreeMap::new();
    let mut binding_factor_inputs: BTreeMap<Identifier<C>, Vec<u8>> = BTreeMap::new();
    let mut binding_factors: BTreeMap<Identifier<C>, BindingFactor<C>> = BTreeMap::new();

    for signer in round_one_outputs["outputs"].as_array().unwrap().iter() {
        let i = signer["identifier"].as_u64().unwrap() as u16;
        let identifier = i.try_into().unwrap();

        let hiding_nonce_randomness =
            hex::decode(signer["hiding_nonce_randomness"].as_str().unwrap()).unwrap();
        hiding_nonces_randomness.insert(identifier, hiding_nonce_randomness);

        let binding_nonce_randomness =
            hex::decode(signer["binding_nonce_randomness"].as_str().unwrap()).unwrap();
        binding_nonces_randomness.insert(identifier, binding_nonce_randomness);

        let signing_nonces = SigningNonces::<C>::from_nonces(
            Nonce::<C>::from_hex(signer["hiding_nonce"].as_str().unwrap()).unwrap(),
            Nonce::<C>::from_hex(signer["binding_nonce"].as_str().unwrap()).unwrap(),
        );

        signer_nonces.insert(identifier, signing_nonces);

        let signing_commitments = SigningCommitments::<C>::new(
            NonceCommitment::from_hex(signer["hiding_nonce_commitment"].as_str().unwrap()).unwrap(),
            NonceCommitment::from_hex(signer["binding_nonce_commitment"].as_str().unwrap())
                .unwrap(),
        );

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

    let mut signature_shares: BTreeMap<Identifier<C>, SignatureShare<C>> = BTreeMap::new();

    for signer in round_two_outputs["outputs"].as_array().unwrap().iter() {
        let i = signer["identifier"].as_u64().unwrap() as u16;
        let sig_share = hex::decode(signer["sig_share"].as_str().unwrap()).unwrap();

        let signature_share = SignatureShare::<C>::deserialize(&sig_share).unwrap();

        signature_shares.insert(i.try_into().unwrap(), signature_share);
    }

    // Final output

    let final_output = &json_vectors["final_output"];

    let signature_bytes = FromHex::from_hex(final_output["sig"].as_str().unwrap()).unwrap();

    TestVectors {
        secret_key,
        verifying_key,
        key_packages,
        message_bytes,
        share_polynomial_coefficients,
        hiding_nonces_randomness,
        binding_nonces_randomness,
        signer_nonces,
        signer_commitments,
        binding_factor_inputs,
        binding_factors,
        signature_shares,
        signature_bytes,
    }
}

/// Test with the given test vectors for a ciphersuite.
pub fn check_sign_with_test_vectors<C: Ciphersuite>(json_vectors: &Value) {
    let TestVectors {
        secret_key,
        verifying_key,
        key_packages,
        message_bytes,
        share_polynomial_coefficients,
        hiding_nonces_randomness,
        binding_nonces_randomness,
        signer_nonces,
        signer_commitments,
        binding_factor_inputs,
        binding_factors,
        signature_shares,
        signature_bytes,
    } = parse_test_vectors(json_vectors);

    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = key_packages.len();
    let min_signers = share_polynomial_coefficients.len() + 1;
    let secret_shares = generate_secret_shares(
        &secret_key,
        max_signers as u16,
        min_signers as u16,
        share_polynomial_coefficients,
        &default_identifiers(max_signers as u16),
    )
    .unwrap();
    let secret_shares: BTreeMap<_, _> = secret_shares
        .iter()
        .map(|share| (share.identifier, share))
        .collect();

    for key_package in key_packages.values() {
        assert_eq!(
            *key_package.verifying_share(),
            frost::keys::VerifyingShare::from(*key_package.signing_share())
        );
        assert_eq!(
            key_package.signing_share(),
            secret_shares[key_package.identifier()].signing_share()
        )
    }

    /////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    /////////////////////////////////////////////////////////////////////////////

    for (i, _) in signer_commitments.clone() {
        let nonces = signer_nonces.get(&i).unwrap();

        // compute nonces from secret and randomness
        let secret = secret_shares[&i].signing_share();

        let hiding_nonce_randomness = &hiding_nonces_randomness[&i];
        let hiding_nonce = Nonce::nonce_generate_from_random_bytes(
            secret,
            hiding_nonce_randomness.as_slice().try_into().unwrap(),
        );
        assert!(nonces.hiding() == &hiding_nonce);

        let binding_nonce_randomness = &binding_nonces_randomness[&i];
        let binding_nonce = Nonce::nonce_generate_from_random_bytes(
            secret,
            binding_nonce_randomness.as_slice().try_into().unwrap(),
        );
        assert!(nonces.binding() == &binding_nonce);

        // compute nonce commitments from nonces
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

    let signing_package = frost::SigningPackage::new(signer_commitments, &message_bytes);

    for (identifier, input) in signing_package
        .binding_factor_preimages(&verifying_key, &[])
        .unwrap()
        .iter()
    {
        assert_eq!(*input, binding_factor_inputs[identifier]);
    }

    let binding_factor_list: frost::BindingFactorList<C> =
        compute_binding_factor_list(&signing_package, &verifying_key, &[]).unwrap();

    for (identifier, binding_factor) in binding_factor_list.0.iter() {
        assert_eq!(*binding_factor, binding_factors[identifier]);
    }

    let mut our_signature_shares = BTreeMap::new();

    // Each participant generates their signature share
    for identifier in signer_nonces.keys() {
        let key_package = &key_packages[identifier];
        let nonces = &signer_nonces[identifier];

        // Each participant generates their signature share.
        let signature_share = frost::round2::sign(&signing_package, nonces, key_package).unwrap();

        our_signature_shares.insert(*identifier, signature_share);
    }

    assert_eq!(our_signature_shares, signature_shares);

    let verifying_shares = key_packages
        .into_iter()
        .map(|(i, key_package)| (i, *key_package.verifying_share()))
        .collect();

    let pubkey_package = frost::keys::PublicKeyPackage::new(verifying_shares, verifying_key);

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation:  collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate the FROST signature from test vector sig shares
    let group_signature_result =
        frost::aggregate(&signing_package, &signature_shares, &pubkey_package);

    // Check that the aggregation passed signature share verification and generation
    assert!(group_signature_result.is_ok());

    // Check that the generated signature matches the test vector signature
    let group_signature = group_signature_result.unwrap();
    assert_eq!(
        group_signature.serialize().unwrap().as_ref(),
        signature_bytes
    );

    // Aggregate the FROST signature from our signature shares
    let group_signature_result =
        frost::aggregate(&signing_package, &our_signature_shares, &pubkey_package);

    // Check that the aggregation passed signature share verification and generation
    assert!(group_signature_result.is_ok());

    // Check that the generated signature matches the test vector signature
    let group_signature = group_signature_result.unwrap();
    assert_eq!(
        group_signature.serialize().unwrap().as_ref(),
        signature_bytes
    );
}
