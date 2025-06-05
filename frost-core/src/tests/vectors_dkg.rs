//! Helper function for testing with test vectors.
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use debugless_unwrap::DebuglessUnwrap;
use hex::{self};
use serde_json::Value;

use crate::{
    keys::{
        dkg::{
            part2, part3, round1::Package as Round1Package, round1::SecretPackage,
            round2::Package as Round2Package,
        },
        generate_secret_polynomial, KeyPackage, PublicKeyPackage, SigningShare,
        VerifiableSecretSharingCommitment, VerifyingShare,
    },
    Ciphersuite, Field, Group, Header, Identifier, Scalar, Signature, SigningKey, VerifyingKey,
};

/// Test vectors for a ciphersuite.
pub struct DKGTestVectors<C: Ciphersuite> {
    secret: SigningKey<C>,
    coefficient: Scalar<C>,
    round1_packages: BTreeMap<Identifier<C>, Round1Package<C>>,
    round2_packages: BTreeMap<Identifier<C>, Round2Package<C>>,
    public_key_package: PublicKeyPackage<C>,
    key_package: KeyPackage<C>,
    participant_id: Identifier<C>,
}

fn json_to_scalar<C: Ciphersuite>(
    vector: &Value,
) -> <<C::Group as Group>::Field as Field>::Serialization {
    (hex::decode(vector.as_str().unwrap()).unwrap())
        .try_into()
        .debugless_unwrap()
}

fn json_to_element<C: Ciphersuite>(vector: &Value) -> <C::Group as Group>::Serialization {
    (hex::decode(vector.as_str().unwrap()).unwrap())
        .try_into()
        .debugless_unwrap()
}

/// Parse test vectors for a given ciphersuite.
#[allow(clippy::type_complexity)]
pub fn parse_test_vectors_dkg<C: Ciphersuite>(json_vectors: &Value) -> Vec<DKGTestVectors<C>> {
    let mut vectors: Vec<DKGTestVectors<C>> = Vec::new();
    let inputs = &json_vectors["inputs"];
    let max_participants = json_vectors["config"]["MAX_PARTICIPANTS"].as_u64().unwrap() as u16;
    let min_signers = json_vectors["config"]["MIN_PARTICIPANTS"].as_u64().unwrap() as u16;

    for i in 1..=max_participants {
        let participant_id_str = &i.to_string();
        let participant_data = &inputs[participant_id_str];
        let participant_id: Identifier<C> = (participant_data["identifier"].as_u64().unwrap()
            as u16)
            .try_into()
            .unwrap();

        let mut round1_packages = BTreeMap::new();
        let mut round2_packages = BTreeMap::new();
        for (other_participant_id_str, other_participant_data) in inputs.as_object().unwrap() {
            if participant_id_str == other_participant_id_str {
                continue;
            }
            match other_participant_id_str.parse::<u16>() {
                Ok(id) => id,
                Err(_) => continue,
            };
            let other_participant_id: Identifier<C> =
                (other_participant_data["identifier"].as_u64().unwrap() as u16)
                    .try_into()
                    .unwrap();
            round1_packages.insert(
                other_participant_id,
                build_round_1_package(other_participant_data),
            );
            round2_packages.insert(
                other_participant_id,
                build_round_2_package(participant_data, other_participant_id_str),
            );
        }

        let secret =
            SigningKey::deserialize(json_to_scalar::<C>(&participant_data["signing_key"]).as_ref())
                .unwrap();

        let coefficient = <<C::Group as Group>::Field as Field>::deserialize(&json_to_scalar::<C>(
            &participant_data["coefficient"],
        ))
        .unwrap();

        let public_key_package = build_public_key_package(json_vectors);

        let verifying_share = VerifyingShare::deserialize(
            json_to_element::<C>(&participant_data["verifying_share"]).as_ref(),
        )
        .unwrap();

        let verifying_key =
            VerifyingKey::deserialize(json_to_element::<C>(&inputs["verifying_key"]).as_ref())
                .unwrap();

        let signing_share = SigningShare::deserialize(
            json_to_scalar::<C>(&participant_data["signing_share"]).as_ref(),
        )
        .unwrap();

        let key_package = KeyPackage {
            header: Header::default(),
            identifier: participant_id,
            signing_share,
            verifying_share,
            verifying_key,
            min_signers,
        };
        vectors.push(DKGTestVectors {
            secret,
            coefficient,
            round1_packages,
            round2_packages,
            public_key_package,
            key_package,
            participant_id,
        })
    }
    vectors
}

fn build_round_1_package<C: Ciphersuite>(json_vectors: &Value) -> Round1Package<C> {
    let vss_commitment = json_vectors["vss_commitments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| json_to_element::<C>(v).as_ref().to_vec())
        .collect::<Vec<Vec<u8>>>();

    let commitment = VerifiableSecretSharingCommitment::deserialize(vss_commitment).unwrap();

    let proof_of_knowledge = Signature::deserialize(
        &hex::decode(json_vectors["proof_of_knowledge"].as_str().unwrap()).unwrap(),
    )
    .debugless_unwrap();

    Round1Package {
        header: Header::default(),
        commitment,
        proof_of_knowledge,
    }
}

fn build_round_2_package<C: Ciphersuite>(
    json_vectors: &Value,
    sender_num: &String,
) -> Round2Package<C> {
    let signing_share = SigningShare::deserialize(
        json_to_scalar::<C>(&json_vectors["signing_shares"][sender_num]).as_ref(),
    )
    .unwrap();

    Round2Package {
        header: Header::default(),
        signing_share,
    }
}

fn build_public_key_package<C: Ciphersuite>(json_vectors: &Value) -> PublicKeyPackage<C> {
    let inputs = &json_vectors["inputs"];

    let mut verifying_shares = BTreeMap::new();

    let max_participants = json_vectors["config"]["MAX_PARTICIPANTS"].as_u64().unwrap() as u8;

    for i in 1..=max_participants {
        let participant_id: Identifier<C> = (inputs[i.to_string()]["identifier"].as_u64().unwrap()
            as u16)
            .try_into()
            .unwrap();
        let verifying_share = VerifyingShare::deserialize(
            json_to_element::<C>(&inputs[i.to_string()]["verifying_share"]).as_ref(),
        )
        .unwrap();
        verifying_shares.insert(participant_id, verifying_share);
    }

    let verifying_key =
        VerifyingKey::deserialize(json_to_element::<C>(&inputs["verifying_key"]).as_ref()).unwrap();

    PublicKeyPackage {
        header: Header::default(),
        verifying_shares,
        verifying_key,
    }
}

/// Test DKG with the given test vectors for a ciphersuite
pub fn check_dkg_keygen<C: Ciphersuite>(json_vectors: &Value) {
    for dkg_vectors in parse_test_vectors_dkg(json_vectors) {
        let DKGTestVectors {
            secret,
            coefficient,
            round1_packages,
            round2_packages,
            public_key_package,
            key_package,
            participant_id,
        } = dkg_vectors;

        let min_signers = 2;
        let max_signers = 3;

        let (coefficients, commitment) = generate_secret_polynomial(
            &secret as &SigningKey<C>,
            max_signers,
            min_signers,
            vec![coefficient],
        )
        .unwrap();

        let round1_secret_package = SecretPackage::new(
            participant_id,
            coefficients,
            commitment.clone(),
            min_signers,
            max_signers,
        );

        let (round2_secret_package, _round2_packages_1) =
            part2(round1_secret_package, &round1_packages).unwrap();

        let (expected_key_package, expected_public_key_package) =
            part3(&round2_secret_package, &round1_packages, &round2_packages).unwrap();

        assert_eq!(public_key_package, expected_public_key_package);
        assert_eq!(key_package, expected_key_package);
    }
}
