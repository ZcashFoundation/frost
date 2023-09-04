//! VerifiableSecretSharingCommitment functions

use std::convert::TryFrom;

use crate::{
    frost::keys::{CoefficientCommitment, VerifiableSecretSharingCommitment},
    tests::helpers::generate_element,
    Group,
};
use debugless_unwrap::DebuglessUnwrap;
use rand_core::{CryptoRng, RngCore};
use serde_json::Value;
use std::collections::HashMap;

use crate::frost::keys::{
    compute_group_commitment, compute_public_key_package, generate_with_dealer, reconstruct,
    IdentifierList, KeyPackage, PublicKeyPackage, SecretShare, SigningShare, VerifyingShare,
};
use crate::{Ciphersuite, Field, VerifyingKey};

/// Test serialize VerifiableSecretSharingCommitment
pub fn check_serialize_vss_commitment<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    // Generate test CoefficientCommitments

    // ---
    let input_1 = generate_element::<C, R>(&mut rng);
    let input_2 = generate_element::<C, R>(&mut rng);
    let input_3 = generate_element::<C, R>(&mut rng);

    let coeff_comms = vec![
        CoefficientCommitment::<C>(input_1),
        CoefficientCommitment(input_2),
        CoefficientCommitment(input_3),
    ];

    //    ---

    let expected = vec![
        <C::Group>::serialize(&input_1),
        <C::Group>::serialize(&input_2),
        <C::Group>::serialize(&input_3),
    ];

    let vss_commitment = VerifiableSecretSharingCommitment(coeff_comms).serialize();

    assert!(expected.len() == vss_commitment.len());
    assert!(expected
        .iter()
        .zip(vss_commitment.iter())
        .all(|(e, c)| e.as_ref() == c.as_ref()));
}

/// Test deserialize VerifiableSecretSharingCommitment
pub fn check_deserialize_vss_commitment<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    // Generate test CoefficientCommitments

    // ---
    let input_1 = generate_element::<C, R>(&mut rng);
    let input_2 = generate_element::<C, R>(&mut rng);
    let input_3 = generate_element::<C, R>(&mut rng);

    let coeff_comms = vec![
        CoefficientCommitment::<C>(input_1),
        CoefficientCommitment(input_2),
        CoefficientCommitment(input_3),
    ];
    // ---

    let expected = VerifiableSecretSharingCommitment(coeff_comms);

    let data = vec![
        <C::Group>::serialize(&input_1),
        <C::Group>::serialize(&input_2),
        <C::Group>::serialize(&input_3),
    ];

    let vss_value = VerifiableSecretSharingCommitment::deserialize(data);

    assert!(vss_value.is_ok());
    assert!(expected == vss_value.unwrap());
}

/// Test deserialize VerifiableSecretSharingCommitment error
pub fn check_deserialize_vss_commitment_error<C: Ciphersuite, R: RngCore + CryptoRng>(
    mut rng: R,
    commitment_helpers: &Value,
) {
    // Generate test CoefficientCommitments

    // ---
    let values = &commitment_helpers["elements"];

    let input_1 = generate_element::<C, R>(&mut rng);
    let input_2 = generate_element::<C, R>(&mut rng);
    let input_3 = generate_element::<C, R>(&mut rng);

    let serialized: <C::Group as Group>::Serialization =
        <C::Group as Group>::Serialization::try_from(
            hex::decode(values["invalid_element"].as_str().unwrap()).unwrap(),
        )
        .debugless_unwrap();
    // ---

    let data = vec![
        <C::Group>::serialize(&input_1),
        <C::Group>::serialize(&input_2),
        <C::Group>::serialize(&input_3),
        serialized,
    ];

    let vss_value = VerifiableSecretSharingCommitment::<C>::deserialize(data);

    assert!(vss_value.is_err());
}

/// Test computing the public key package from a list of commitments.
pub fn check_compute_public_key_package<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    let max_signers = 3;
    let min_signers = 2;
    let (secret_shares, public_key_package) =
        generate_with_dealer::<C, _>(max_signers, min_signers, IdentifierList::Default, &mut rng)
            .unwrap();
    let commitments: Vec<_> = secret_shares
        .values()
        .map(|secret_share| secret_share.commitment().clone())
        .collect();
    let members = secret_shares.keys().copied().collect();
    let group_commitment = compute_group_commitment(&commitments);
    let mut group_public = VerifyingKey::new(<C::Group>::identity());
    let mut signing_shares = HashMap::new();
    let mut verifying_shares = HashMap::new();
    for _ in 0..max_signers {
        group_public = VerifyingKey::new(
            group_public.to_element() + public_key_package.group_public().to_element(),
        );
        for (id, verifying_share) in public_key_package.signer_pubkeys() {
            let entry = verifying_shares
                .entry(*id)
                .or_insert_with(|| VerifyingShare::new(<C::Group>::identity()));
            *entry = VerifyingShare::new(entry.to_element() + verifying_share.to_element());
        }
        for (id, secret_share) in &secret_shares {
            let entry = signing_shares
                .entry(*id)
                .or_insert_with(|| SigningShare::<C>::new(<C::Group as Group>::Field::zero()));
            *entry = SigningShare::new(entry.to_scalar() + secret_share.value().to_scalar());
        }
    }
    let secret_shares = signing_shares
        .iter()
        .map(|(id, signing_share)| {
            SecretShare::new(*id, signing_share.clone(), group_commitment.clone())
        })
        .collect::<Vec<_>>();
    let public_key_package = PublicKeyPackage::new(verifying_shares, group_public);
    assert_eq!(
        public_key_package,
        compute_public_key_package(&members, &group_commitment)
    );
    let signing_key = reconstruct(&secret_shares[..min_signers as usize]).unwrap();
    assert_eq!(
        *public_key_package.group_public(),
        VerifyingKey::from(signing_key)
    );
    for secret_share in secret_shares {
        KeyPackage::try_from(secret_share).unwrap();
    }
}
