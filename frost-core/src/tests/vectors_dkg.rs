//! Helper function for testing with test vectors.
use alloc::{collections::BTreeMap, string::ToString, vec::Vec};

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
pub fn parse_test_vectors_dkg<C: Ciphersuite>(json_vectors: &Value) -> DKGTestVectors<C> {
    let inputs = &json_vectors["inputs"];
    let participant = &inputs["1"];

    let participant_1_id: Identifier<C> = (participant["identifier"].as_u64().unwrap() as u16)
        .try_into()
        .unwrap();
    let participant_2_id: Identifier<C> = (inputs["2"]["identifier"].as_u64().unwrap() as u16)
        .try_into()
        .unwrap();
    let participant_3_id: Identifier<C> = (inputs["3"]["identifier"].as_u64().unwrap() as u16)
        .try_into()
        .unwrap();

    let mut round1_packages = BTreeMap::new();
    round1_packages.insert(participant_2_id, build_round_1_package(json_vectors, 2));
    round1_packages.insert(participant_3_id, build_round_1_package(json_vectors, 3));

    let mut round2_packages = BTreeMap::new();
    round2_packages.insert(participant_2_id, build_round_2_package(json_vectors, 2));
    round2_packages.insert(participant_3_id, build_round_2_package(json_vectors, 3));

    let secret =
        SigningKey::deserialize(json_to_scalar::<C>(&participant["signing_key"]).as_ref()).unwrap();

    let coefficient = <<C::Group as Group>::Field as Field>::deserialize(&json_to_scalar::<C>(
        &participant["coefficient"],
    ))
    .unwrap();

    let public_key_package = build_public_key_package(json_vectors);

    let verifying_share =
        VerifyingShare::deserialize(json_to_element::<C>(&participant["verifying_share"]).as_ref())
            .unwrap();

    let verifying_key =
        VerifyingKey::deserialize(json_to_element::<C>(&inputs["verifying_key"]).as_ref()).unwrap();

    let signing_share =
        SigningShare::deserialize(json_to_scalar::<C>(&participant["signing_share"]).as_ref())
            .unwrap();

    let key_package = KeyPackage {
        header: Header::default(),
        identifier: participant_1_id,
        signing_share,
        verifying_share,
        verifying_key,
        min_signers: 2,
    };

    DKGTestVectors {
        secret,
        coefficient,
        round1_packages,
        round2_packages,
        public_key_package,
        key_package,
        participant_id: participant_1_id,
    }
}

fn build_round_1_package<C: Ciphersuite>(
    json_vectors: &Value,
    participant_num: usize,
) -> Round1Package<C> {
    let inputs = &json_vectors["inputs"];
    let participant = &inputs[participant_num.to_string()];
    let vss_commitment = participant["vss_commitments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| json_to_element::<C>(v).as_ref().to_vec())
        .collect::<Vec<Vec<u8>>>();

    let commitment = VerifiableSecretSharingCommitment::deserialize(vss_commitment).unwrap();

    let proof_of_knowledge = Signature::deserialize(
        &hex::decode(participant["proof_of_knowledge"].as_str().unwrap()).unwrap(),
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
    sender_num: usize,
) -> Round2Package<C> {
    let inputs = &json_vectors["inputs"];

    let signing_share = SigningShare::deserialize(
        json_to_scalar::<C>(&inputs["1"]["signing_shares"][sender_num.to_string()]).as_ref(),
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
    let DKGTestVectors {
        secret,
        coefficient,
        round1_packages,
        round2_packages,
        public_key_package,
        key_package,
        participant_id,
    } = parse_test_vectors_dkg(json_vectors);

    let min_signers = 2;
    let max_signers = 3;

    let (coefficients, commitment) = generate_secret_polynomial(
        &secret as &SigningKey<C>,
        max_signers,
        min_signers,
        vec![coefficient],
    )
    .unwrap();

    let round1_secret_package = SecretPackage {
        identifier: participant_id,
        coefficients,
        commitment: commitment.clone(),
        min_signers,
        max_signers,
    };

    let (round2_secret_package, _round2_packages_1) =
        part2(round1_secret_package, &round1_packages).unwrap();

    let (expected_key_package, expected_public_key_package) =
        part3(&round2_secret_package, &round1_packages, &round2_packages).unwrap();

    assert_eq!(public_key_package, expected_public_key_package);
    assert_eq!(key_package, expected_key_package);
}
