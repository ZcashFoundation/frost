//! Ciphersuite-generic test functions.
#![allow(clippy::type_complexity)]
#![cfg(feature = "serialization")]

use alloc::{borrow::ToOwned, collections::BTreeMap, vec::Vec};
use rand_core::{CryptoRng, RngCore};

use crate as frost;
use crate::keys::cocktail_dkg::CocktailCiphersuite;
use crate::keys::dkg::{round1, round2};
use crate::keys::{SecretShare, SigningShare};
use crate::round1::SigningNonces;
use crate::round2::SignatureShare;
use crate::{
    keys::PublicKeyPackage, Error, Field, Group, Identifier, Signature, SigningKey, SigningPackage,
    VerifyingKey,
};

use crate::Ciphersuite;

/// Test if creating a zero SigningKey fails
pub fn check_zero_key_fails<C: Ciphersuite>() {
    let zero = <<<C as Ciphersuite>::Group as Group>::Field>::zero();
    let encoded_zero = <<<C as Ciphersuite>::Group as Group>::Field>::serialize(&zero);
    let r = SigningKey::<C>::deserialize(encoded_zero.as_ref());
    assert_eq!(r, Err(Error::MalformedSigningKey));
}

/// Test share generation with a Ciphersuite
pub fn check_share_generation<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    let secret = crate::SigningKey::<C>::new(&mut rng);
    // Simulate serialization / deserialization to ensure it works
    let secret = SigningKey::deserialize(&secret.serialize()).unwrap();

    let max_signers = 5;
    let min_signers = 3;

    let coefficients =
        frost::keys::generate_coefficients::<C, _>(min_signers as usize - 1, &mut rng);

    let secret_shares = frost::keys::generate_secret_shares(
        &secret,
        max_signers,
        min_signers,
        coefficients,
        &frost::keys::default_identifiers(max_signers),
    )
    .unwrap();

    let key_packages: Vec<frost::keys::KeyPackage<C>> = secret_shares
        .iter()
        .cloned()
        .map(|s| s.try_into().unwrap())
        .collect();

    assert_eq!(
        frost::keys::reconstruct::<C>(&key_packages)
            .unwrap()
            .serialize(),
        secret.serialize()
    );

    // Test error cases

    assert_eq!(
        frost::keys::reconstruct::<C>(&[]).unwrap_err(),
        Error::IncorrectNumberOfShares
    );

    assert_eq!(
        frost::keys::reconstruct::<C>(&key_packages[0..1]).unwrap_err(),
        Error::IncorrectNumberOfShares
    );

    let mut key_packages = key_packages;
    key_packages[0] = key_packages[1].clone();

    assert_eq!(
        frost::keys::reconstruct::<C>(&key_packages).unwrap_err(),
        Error::DuplicatedIdentifier
    );
}

/// Test share generation with a Ciphersuite
pub fn check_share_generation_fails_with_invalid_signers<C: Ciphersuite, R: RngCore + CryptoRng>(
    min_signers: u16,
    max_signers: u16,
    error: Error<C>,
    mut rng: R,
) {
    let secret = crate::SigningKey::<C>::new(&mut rng);

    // Use arbitrary number of coefficients so tests don't fail for overflow reasons
    let coefficients = frost::keys::generate_coefficients::<C, _>(3, &mut rng);

    let secret_shares = frost::keys::generate_secret_shares(
        &secret,
        max_signers,
        min_signers,
        coefficients,
        &frost::keys::default_identifiers(max_signers),
    );

    assert!(secret_shares.is_err());
    assert!(secret_shares == Err(error))
}

/// Test FROST signing with trusted dealer with a Ciphersuite.
pub fn check_sign_with_dealer<C: Ciphersuite, R: RngCore + CryptoRng>(
    mut rng: R,
) -> (Vec<u8>, Signature<C>, VerifyingKey<C>) {
    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;
    let (shares, pub_key_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();
    // Simulate serialization / deserialization to ensure it works
    let pub_key_package =
        PublicKeyPackage::deserialize(&pub_key_package.serialize().unwrap()).unwrap();

    // Verifies the secret shares from the dealer
    let mut key_packages: BTreeMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> =
        BTreeMap::new();

    for (k, v) in shares {
        // Simulate serialization / deserialization to ensure it works
        let v = SecretShare::<C>::deserialize(&v.serialize().unwrap()).unwrap();
        let key_package = frost::keys::KeyPackage::try_from(v).unwrap();
        // Simulate serialization / deserialization to ensure it works
        let key_package =
            frost::keys::KeyPackage::deserialize(&key_package.serialize().unwrap()).unwrap();
        key_packages.insert(k, key_package);
    }
    // Check if it fails with not enough signers. Usually this would return an
    // error before even running the signing procedure, because `KeyPackage`
    // contains the correct `min_signers` value and the signing procedure checks
    // if the number of shares is at least `min_signers`. To bypass the check
    // and test if the protocol itself fails with not enough signers, we modify
    // the `KeyPackages`s, decrementing their saved `min_signers` value before
    // running the signing procedure.
    let r = check_sign(
        min_signers - 1,
        key_packages
            .iter()
            .map(|(id, k)| {
                // Decrement `min_signers` as explained above and use
                // the updated `KeyPackage`.
                let mut k = k.clone();
                k.min_signers -= 1;
                (*id, k)
            })
            .collect(),
        &mut rng,
        pub_key_package.clone(),
    );
    assert_eq!(r, Err(Error::InvalidSignature));

    check_sign(min_signers, key_packages, rng, pub_key_package).unwrap()
}

/// Test FROST signing with trusted dealer fails with invalid numbers of signers.
pub fn check_sign_with_dealer_fails_with_invalid_signers<C: Ciphersuite, R: RngCore + CryptoRng>(
    min_signers: u16,
    max_signers: u16,
    error: Error<C>,
    mut rng: R,
) {
    let out = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default::<C>,
        &mut rng,
    );

    assert!(out.is_err());
    assert!(out == Err(error))
}

/// Test DKG part1 fails with invalid numbers of signers.
pub fn check_dkg_part1_fails_with_invalid_signers<C: Ciphersuite, R: RngCore + CryptoRng>(
    min_signers: u16,
    max_signers: u16,
    error: Error<C>,
    mut rng: R,
) {
    let out = frost::keys::dkg::part1(
        Identifier::try_from(1).unwrap(),
        max_signers,
        min_signers,
        &mut rng,
    );

    assert!(out.is_err());
    assert!(out == Err(error))
}

/// Test FROST signing with the given shares.
pub fn check_sign<C: Ciphersuite + PartialEq, R: RngCore + CryptoRng>(
    min_signers: u16,
    key_packages: BTreeMap<frost::Identifier<C>, frost::keys::KeyPackage<C>>,
    mut rng: R,
    pubkey_package: PublicKeyPackage<C>,
) -> Result<(Vec<u8>, Signature<C>, VerifyingKey<C>), Error<C>> {
    let mut nonces_map: BTreeMap<frost::Identifier<C>, frost::round1::SigningNonces<C>> =
        BTreeMap::new();
    let mut commitments_map: BTreeMap<frost::Identifier<C>, frost::round1::SigningCommitments<C>> =
        BTreeMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    for participant_identifier in key_packages.keys().take(min_signers as usize) {
        // Simulate serialization / deserialization to ensure it works
        let participant_identifier =
            Identifier::deserialize(&participant_identifier.serialize()).unwrap();
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _min_signers_.
        let (nonces, commitments) = frost::round1::commit(
            key_packages
                .get(&participant_identifier)
                .unwrap()
                .signing_share(),
            &mut rng,
        );
        // Simulate serialization / deserialization to ensure it works
        let nonces = SigningNonces::deserialize(&nonces.serialize().unwrap()).unwrap();
        let commitments =
            frost::round1::SigningCommitments::deserialize(&commitments.serialize().unwrap())
                .unwrap();
        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares = BTreeMap::new();
    let message = "message to sign".as_bytes();
    let signing_package = SigningPackage::new(commitments_map, message);
    // Simulate serialization / deserialization to ensure it works
    let signing_package =
        SigningPackage::deserialize(&signing_package.serialize().unwrap()).unwrap();

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    for participant_identifier in nonces_map.keys() {
        let key_package = key_packages.get(participant_identifier).unwrap();

        let nonces_to_use = nonces_map.get(participant_identifier).unwrap();

        check_sign_errors(
            signing_package.clone(),
            nonces_to_use.clone(),
            key_package.clone(),
        );

        // Each participant generates their signature share.
        let signature_share = frost::round2::sign(&signing_package, nonces_to_use, key_package)?;
        // Simulate serialization / deserialization to ensure it works
        let signature_share = SignatureShare::deserialize(&signature_share.serialize()).unwrap();
        signature_shares.insert(*participant_identifier, signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    check_aggregate_errors(
        signing_package.clone(),
        signature_shares.clone(),
        pubkey_package.clone(),
    );

    check_verifying_shares(
        pubkey_package.clone(),
        signing_package.clone(),
        signature_shares.clone(),
    );

    check_verify_signature_share(&pubkey_package, &signing_package, &signature_shares);

    // Aggregate (also verifies the signature shares)
    let group_signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;
    // Simulate serialization / deserialization to ensure it works
    let group_signature = Signature::deserialize(&group_signature.serialize().unwrap()).unwrap();

    // Check that the threshold signature can be verified by the group public
    // key (the verification key).
    pubkey_package
        .verifying_key
        .verify(message, &group_signature)?;

    // Check that the threshold signature can be verified by the group public
    // key (the verification key) from KeyPackage.verifying_key
    for (participant_identifier, _) in nonces_map.clone() {
        let key_package = key_packages.get(&participant_identifier).unwrap();

        key_package
            .verifying_key
            .verify(message, &group_signature)?;
    }

    Ok((
        message.to_owned(),
        group_signature,
        pubkey_package.verifying_key,
    ))
}

fn check_sign_errors<C: Ciphersuite + PartialEq>(
    signing_package: frost::SigningPackage<C>,
    signing_nonces: frost::round1::SigningNonces<C>,
    key_package: frost::keys::KeyPackage<C>,
) {
    // Check if passing not enough commitments causes an error

    let mut commitments = signing_package.signing_commitments().clone();
    // Remove one commitment that's not from the key_package owner
    let id = *commitments
        .keys()
        .find(|&&id| id != key_package.identifier)
        .unwrap();
    commitments.remove(&id);
    let signing_package = frost::SigningPackage::new(commitments, signing_package.message());

    let r = frost::round2::sign(&signing_package, &signing_nonces, &key_package);
    assert_eq!(r, Err(Error::IncorrectNumberOfCommitments));
}

fn check_aggregate_errors<C: Ciphersuite + PartialEq>(
    signing_package: frost::SigningPackage<C>,
    signature_shares: BTreeMap<frost::Identifier<C>, frost::round2::SignatureShare<C>>,
    pubkey_package: frost::keys::PublicKeyPackage<C>,
) {
    check_aggregate_corrupted_share(
        signing_package.clone(),
        signature_shares.clone(),
        pubkey_package.clone(),
    );

    check_aggregate_invalid_share_identifier_for_verifying_shares(
        signing_package,
        signature_shares,
        pubkey_package,
    );
}

fn check_aggregate_corrupted_share<C: Ciphersuite + PartialEq>(
    signing_package: frost::SigningPackage<C>,
    mut signature_shares: BTreeMap<frost::Identifier<C>, frost::round2::SignatureShare<C>>,
    pubkey_package: frost::keys::PublicKeyPackage<C>,
) {
    use crate::{round2::SignatureShare, CheaterDetection};

    let one = <<C as Ciphersuite>::Group as Group>::Field::one();
    // Corrupt two shares
    let id1 = *signature_shares.keys().next().unwrap();
    *signature_shares.get_mut(&id1).unwrap() =
        SignatureShare::new(signature_shares[&id1].to_scalar() + one);
    let id2 = *signature_shares.keys().nth(1).unwrap();
    *signature_shares.get_mut(&id2).unwrap() =
        SignatureShare::new(signature_shares[&id2].to_scalar() + one);

    let e = frost::aggregate(&signing_package, &signature_shares, &pubkey_package).unwrap_err();
    assert_eq!(e.culprits(), vec![id1]);
    assert_eq!(
        e,
        Error::InvalidSignatureShare {
            culprits: vec![id1]
        }
    );

    let e = frost::aggregate_custom(
        &signing_package,
        &signature_shares,
        &pubkey_package,
        crate::CheaterDetection::Disabled,
    )
    .unwrap_err();
    assert_eq!(e.culprits(), vec![]);
    assert_eq!(e, Error::InvalidSignature);

    let e = frost::aggregate_custom(
        &signing_package,
        &signature_shares,
        &pubkey_package,
        crate::CheaterDetection::FirstCheater,
    )
    .unwrap_err();
    assert_eq!(e.culprits(), vec![id1]);
    assert_eq!(
        e,
        Error::InvalidSignatureShare {
            culprits: vec![id1]
        }
    );

    let e = frost::aggregate_custom(
        &signing_package,
        &signature_shares,
        &pubkey_package,
        CheaterDetection::AllCheaters,
    )
    .unwrap_err();
    assert_eq!(e.culprits(), vec![id1, id2]);
    assert_eq!(
        e,
        Error::InvalidSignatureShare {
            culprits: vec![id1, id2]
        }
    );
}

/// Test NCC-E008263-4VP audit finding (PublicKeyPackage).
/// Note that the SigningPackage part of the finding is not currently reachable
/// since it's caught by `compute_lagrange_coefficient()`, and the Binding Factor
/// part can't either since it's caught before by the PublicKeyPackage part.
fn check_aggregate_invalid_share_identifier_for_verifying_shares<C: Ciphersuite + PartialEq>(
    signing_package: frost::SigningPackage<C>,
    mut signature_shares: BTreeMap<frost::Identifier<C>, frost::round2::SignatureShare<C>>,
    pubkey_package: frost::keys::PublicKeyPackage<C>,
) {
    let invalid_identifier = Identifier::derive("invalid identifier".as_bytes()).unwrap();
    // Insert a new share (copied from other existing share) with an invalid identifier
    signature_shares.insert(
        invalid_identifier,
        *signature_shares.values().next().unwrap(),
    );
    // Should error, but not panic
    frost::aggregate(&signing_package, &signature_shares, &pubkey_package)
        .expect_err("should not work");
}

/// Test FROST signing with DKG with a Ciphersuite.
pub fn check_sign_with_dkg<C: Ciphersuite + PartialEq, R: RngCore + CryptoRng>(
    mut rng: R,
) -> (Vec<u8>, Signature<C>, VerifyingKey<C>)
where
    C::Group: core::cmp::PartialEq,
{
    ////////////////////////////////////////////////////////////////////////////
    // Key generation, Round 1
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;

    // Keep track of each participant's round 1 secret package.
    // In practice each participant will keep its copy; no one
    // will have all the participant's packages.
    let mut round1_secret_packages: BTreeMap<
        frost::Identifier<C>,
        frost::keys::dkg::round1::SecretPackage<C>,
    > = BTreeMap::new();

    // Keep track of all round 1 packages sent to the given participant.
    // This is used to simulate the broadcast; in practice the packages
    // will be sent through some communication channel.
    let mut received_round1_packages: BTreeMap<
        frost::Identifier<C>,
        BTreeMap<frost::Identifier<C>, frost::keys::dkg::round1::Package<C>>,
    > = BTreeMap::new();

    // For each participant, perform the first part of the DKG protocol.
    // In practice, each participant will perform this on their own environments.
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let (round1_secret_package, round1_package) =
            frost::keys::dkg::part1(participant_identifier, max_signers, min_signers, &mut rng)
                .unwrap();

        // Simulate serialization / deserialization to ensure it works
        let round1_secret_package = frost::keys::dkg::round1::SecretPackage::<C>::deserialize(
            &round1_secret_package.serialize().unwrap(),
        )
        .unwrap();
        let round1_package = frost::keys::dkg::round1::Package::<C>::deserialize(
            &round1_package.serialize().unwrap(),
        )
        .unwrap();

        // Store the participant's secret package for later use.
        // In practice each participant will store it in their own environment.
        round1_secret_packages.insert(
            participant_identifier,
            // Serialization roundtrip to simulate storage for later
            round1::SecretPackage::deserialize(&round1_secret_package.serialize().unwrap())
                .unwrap(),
        );

        // "Send" the round 1 package to all other participants. In this
        // test this is simulated using a BTreeMap; in practice this will be
        // sent through some communication channel.
        for receiver_participant_index in 1..=max_signers {
            if receiver_participant_index == participant_index {
                continue;
            }
            let receiver_participant_identifier = receiver_participant_index
                .try_into()
                .expect("should be nonzero");
            received_round1_packages
                .entry(receiver_participant_identifier)
                .or_default()
                .insert(
                    participant_identifier,
                    // Serialization roundtrip to simulate communication
                    round1::Package::deserialize(&round1_package.serialize().unwrap()).unwrap(),
                );
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Key generation, Round 2
    ////////////////////////////////////////////////////////////////////////////

    // Keep track of each participant's round 2 secret package.
    // In practice each participant will keep its copy; no one
    // will have all the participant's packages.
    let mut round2_secret_packages = BTreeMap::new();

    // Keep track of all round 2 packages sent to the given participant.
    // This is used to simulate the broadcast; in practice the packages
    // will be sent through some communication channel.
    let mut received_round2_packages = BTreeMap::new();

    // For each participant, perform the second part of the DKG protocol.
    // In practice, each participant will perform this on their own environments.
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let round1_secret_package = round1_secret_packages
            .remove(&participant_identifier)
            .unwrap();
        let round1_packages = &received_round1_packages[&participant_identifier];
        check_part2_error(round1_secret_package.clone(), round1_packages.clone());
        let (round2_secret_package, round2_packages) =
            frost::keys::dkg::part2(round1_secret_package, round1_packages).expect("should work");

        // Simulate serialization / deserialization to ensure it works
        let round2_secret_package = frost::keys::dkg::round2::SecretPackage::<C>::deserialize(
            &round2_secret_package.serialize().unwrap(),
        )
        .unwrap();

        // Store the participant's secret package for later use.
        // In practice each participant will store it in their own environment.
        round2_secret_packages.insert(
            participant_identifier,
            // Serialization roundtrip to simulate storage for later
            round2::SecretPackage::deserialize(&round2_secret_package.serialize().unwrap())
                .unwrap(),
        );

        // "Send" the round 2 package to all other participants. In this
        // test this is simulated using a BTreeMap; in practice this will be
        // sent through some communication channel.
        // Note that, in contrast to the previous part, here each other participant
        // gets its own specific package.
        for (receiver_identifier, round2_package) in round2_packages {
            // Simulate serialization / deserialization to ensure it works
            let round2_package = frost::keys::dkg::round2::Package::<C>::deserialize(
                &round2_package.serialize().unwrap(),
            )
            .unwrap();
            received_round2_packages
                .entry(receiver_identifier)
                .or_insert_with(BTreeMap::new)
                .insert(
                    participant_identifier,
                    // Serialization roundtrip to simulate communication
                    round2::Package::deserialize(&round2_package.serialize().unwrap()).unwrap(),
                );
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Key generation, final computation
    ////////////////////////////////////////////////////////////////////////////

    // Keep track of each participant's long-lived key package.
    // In practice each participant will keep its copy; no one
    // will have all the participant's packages.
    let mut key_packages = BTreeMap::new();

    // Map of the verifying share of each participant.
    // Used by the signing test that follows.
    let mut verifying_shares = BTreeMap::new();
    // The group public key, used by the signing test that follows.
    let mut verifying_key = None;
    // For each participant, store the set of verifying keys they have computed.
    // This is used to check if the set is correct (the same) for all participants.
    // In practice, if there is a Coordinator, only they need to store the set.
    // If there is not, then all candidates must store their own sets.
    // The verifying keys are used to verify the signature shares produced
    // for each signature before being aggregated.
    let mut pubkey_packages_by_participant = BTreeMap::new();

    check_part3_errors(
        max_signers,
        round2_secret_packages.clone(),
        received_round1_packages.clone(),
        received_round2_packages.clone(),
    );

    // For each participant, perform the third part of the DKG protocol.
    // In practice, each participant will perform this on their own environments.
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let (key_package, pubkey_package_for_participant) = frost::keys::dkg::part3(
            &round2_secret_packages[&participant_identifier],
            &received_round1_packages[&participant_identifier],
            &received_round2_packages[&participant_identifier],
        )
        .unwrap();
        // Simulate serialization / deserialization to ensure it works
        let key_package =
            frost::keys::KeyPackage::deserialize(&key_package.serialize().unwrap()).unwrap();
        let pubkey_package_for_participant = frost::keys::PublicKeyPackage::deserialize(
            &pubkey_package_for_participant.serialize().unwrap(),
        )
        .unwrap();
        verifying_shares.insert(participant_identifier, key_package.verifying_share);
        // Test if all verifying_key are equal
        if let Some(previous_verifying_key) = verifying_key {
            assert_eq!(previous_verifying_key, key_package.verifying_key)
        }
        verifying_key = Some(key_package.verifying_key);
        key_packages.insert(participant_identifier, key_package);
        pubkey_packages_by_participant
            .insert(participant_identifier, pubkey_package_for_participant);
    }

    // Test if the set of verifying keys is correct for all participants.
    for verifying_keys_for_participant in pubkey_packages_by_participant.values() {
        assert!(verifying_keys_for_participant.verifying_shares == verifying_shares);
    }

    let pubkeys = pubkey_packages_by_participant
        .first_key_value()
        .unwrap()
        .1
        .clone();
    // Simulate serialization / deserialization to ensure it works
    let pubkeys =
        frost::keys::PublicKeyPackage::deserialize(&pubkeys.serialize().unwrap()).unwrap();

    // Proceed with the signing test.
    check_sign(min_signers, key_packages, rng, pubkeys).unwrap()
}

/// Check for error cases related to DKG part3.
fn check_part3_errors<C: Ciphersuite>(
    max_signers: u16,
    round2_secret_packages: BTreeMap<Identifier<C>, frost::keys::dkg::round2::SecretPackage<C>>,
    received_round1_packages: BTreeMap<
        Identifier<C>,
        BTreeMap<Identifier<C>, frost::keys::dkg::round1::Package<C>>,
    >,
    received_round2_packages: BTreeMap<
        Identifier<C>,
        BTreeMap<Identifier<C>, frost::keys::dkg::round2::Package<C>>,
    >,
) {
    check_part3_different_participants(
        max_signers,
        round2_secret_packages.clone(),
        received_round1_packages.clone(),
        received_round2_packages.clone(),
    );
    check_part3_corrupted_share(
        max_signers,
        round2_secret_packages,
        received_round1_packages,
        received_round2_packages,
    );
}

/// Check that calling dkg::part3() with distinct sets of participants fail.
pub fn check_part3_different_participants<C: Ciphersuite>(
    max_signers: u16,
    round2_secret_packages: BTreeMap<Identifier<C>, frost::keys::dkg::round2::SecretPackage<C>>,
    received_round1_packages: BTreeMap<
        Identifier<C>,
        BTreeMap<Identifier<C>, frost::keys::dkg::round1::Package<C>>,
    >,
    received_round2_packages: BTreeMap<
        Identifier<C>,
        BTreeMap<Identifier<C>, frost::keys::dkg::round2::Package<C>>,
    >,
) {
    // For each participant, perform the third part of the DKG protocol.
    // In practice, each participant will perform this on their own environments.
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");

        // Remove the first package from the map, and reinsert it with an unrelated
        // Do the same for Round 2 packages
        let mut received_round2_packages =
            received_round2_packages[&participant_identifier].clone();
        let package = received_round2_packages
            .remove(&received_round2_packages.keys().next().unwrap().clone())
            .unwrap();
        received_round2_packages.insert(42u16.try_into().unwrap(), package);

        let r = frost::keys::dkg::part3(
            &round2_secret_packages[&participant_identifier],
            &received_round1_packages[&participant_identifier],
            &received_round2_packages,
        )
        .expect_err("Should have failed due to different identifier sets");
        assert_eq!(r, Error::IncorrectPackage)
    }
}

/// Check that calling dkg::part3() with a corrupted share fail, and the
/// culprit is correctly identified.
fn check_part3_corrupted_share<C: Ciphersuite>(
    max_signers: u16,
    round2_secret_packages: BTreeMap<Identifier<C>, frost::keys::dkg::round2::SecretPackage<C>>,
    received_round1_packages: BTreeMap<
        Identifier<C>,
        BTreeMap<Identifier<C>, frost::keys::dkg::round1::Package<C>>,
    >,
    received_round2_packages: BTreeMap<
        Identifier<C>,
        BTreeMap<Identifier<C>, frost::keys::dkg::round2::Package<C>>,
    >,
) {
    // For each participant, perform the third part of the DKG protocol.
    // In practice, each participant will perform this on their own environments.
    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");

        // Remove the first package from the map, and reinsert it with an unrelated
        // Do the same for Round 2 packages
        let mut received_round2_packages =
            received_round2_packages[&participant_identifier].clone();
        let culprit = *received_round2_packages.keys().next().unwrap();
        let package = received_round2_packages.get_mut(&culprit).unwrap();
        let one = <<C as Ciphersuite>::Group as Group>::Field::one();
        package.signing_share = SigningShare::new(package.signing_share().to_scalar() + one);

        let r = frost::keys::dkg::part3(
            &round2_secret_packages[&participant_identifier],
            &received_round1_packages[&participant_identifier],
            &received_round2_packages,
        )
        .expect_err("Should have failed due to corrupted share");
        assert_eq!(
            r,
            Error::InvalidSecretShare {
                culprit: Some(culprit)
            }
        )
    }
}

/// Test FROST signing with trusted dealer with a Ciphersuite, using specified
/// Identifiers.
pub fn check_sign_with_dealer_and_identifiers<C: Ciphersuite, R: RngCore + CryptoRng>(
    mut rng: R,
) -> (Vec<u8>, Signature<C>, VerifyingKey<C>) {
    // Check error cases first
    // Check repeated identifiers

    let identifiers: Vec<frost::Identifier<C>> = [1u16, 42, 100, 257, 42]
        .into_iter()
        .map(|i| i.try_into().unwrap())
        .collect();
    let max_signers = 5;
    let min_signers = 3;
    let err = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Custom(&identifiers),
        &mut rng,
    )
    .unwrap_err();
    assert_eq!(err, Error::DuplicatedIdentifier);

    // Check incorrect number of identifiers

    let identifiers: Vec<frost::Identifier<C>> = [1u16, 42, 100, 257]
        .into_iter()
        .map(|i| i.try_into().unwrap())
        .collect();
    let max_signers = 5;
    let min_signers = 3;
    let err = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Custom(&identifiers),
        &mut rng,
    )
    .unwrap_err();
    assert_eq!(err, Error::IncorrectNumberOfIdentifiers);

    // Check correct case

    let identifiers: Vec<frost::Identifier<C>> = [1u16, 42, 100, 257, 65535]
        .into_iter()
        .map(|i| i.try_into().unwrap())
        .collect();

    let max_signers = 5;
    let min_signers = 3;
    let (shares, pubkeys) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Custom(&identifiers),
        &mut rng,
    )
    .unwrap();

    // Check if the specified identifiers were used
    for id in identifiers {
        assert!(shares.contains_key(&id));
    }

    // Do regular testing to make sure it works

    let mut key_packages: BTreeMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> =
        BTreeMap::new();
    for (k, v) in shares {
        let key_package = frost::keys::KeyPackage::try_from(v).unwrap();
        key_packages.insert(k, key_package);
    }
    check_sign(min_signers, key_packages, rng, pubkeys).unwrap()
}

// Check for error cases in DKG part 2.
fn check_part2_error<C: Ciphersuite>(
    round1_secret_package: frost::keys::dkg::round1::SecretPackage<C>,
    mut round1_packages: BTreeMap<frost::Identifier<C>, frost::keys::dkg::round1::Package<C>>,
) {
    // Check if a corrupted proof of knowledge results in failure.
    let one = <<C as Ciphersuite>::Group as Group>::Field::one();
    // Corrupt a PoK
    let id = *round1_packages.keys().next().unwrap();
    round1_packages.get_mut(&id).unwrap().proof_of_knowledge.z =
        round1_packages[&id].proof_of_knowledge.z + one;
    let e = frost::keys::dkg::part2(round1_secret_package, &round1_packages).unwrap_err();
    assert_eq!(e.culprits(), vec![id]);
    assert_eq!(e, Error::InvalidProofOfKnowledge { culprit: id });
}

/// Test Error culprit method.
pub fn check_error_culprit<C: Ciphersuite>() {
    let identifier: frost::Identifier<C> = 42u16.try_into().unwrap();

    let e = Error::InvalidSignatureShare {
        culprits: vec![identifier],
    };
    assert_eq!(e.culprits(), vec![identifier]);

    let e = Error::InvalidProofOfKnowledge {
        culprit: identifier,
    };
    assert_eq!(e.culprits(), vec![identifier]);

    let e: Error<C> = Error::InvalidSignature;
    assert_eq!(e.culprits(), vec![]);
}

/// Test identifier derivation with a Ciphersuite
pub fn check_identifier_derivation<C: Ciphersuite>() {
    let id1a = Identifier::<C>::derive("username1".as_bytes()).unwrap();
    let id1b = Identifier::<C>::derive("username1".as_bytes()).unwrap();
    let id2 = Identifier::<C>::derive("username2".as_bytes()).unwrap();

    assert!(id1a == id1b);
    assert!(id1a != id2);
}

/// Checks the signer's identifier is included in the package
pub fn check_sign_with_missing_identifier<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;
    let (shares, _pubkeys) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();

    // Verifies the secret shares from the dealer
    let mut key_packages: BTreeMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> =
        BTreeMap::new();

    for (k, v) in shares {
        let key_package = frost::keys::KeyPackage::try_from(v).unwrap();
        key_packages.insert(k, key_package);
    }

    let mut nonces_map: BTreeMap<frost::Identifier<C>, frost::round1::SigningNonces<C>> =
        BTreeMap::new();
    let mut commitments_map: BTreeMap<frost::Identifier<C>, frost::round1::SigningCommitments<C>> =
        BTreeMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    let id_1 = Identifier::<C>::try_from(1).unwrap();
    let id_2 = Identifier::<C>::try_from(2).unwrap();
    let id_3 = Identifier::<C>::try_from(3).unwrap();
    let id_4 = Identifier::<C>::try_from(4).unwrap();
    let key_packages_inc = vec![id_1, id_2, id_3];

    for participant_identifier in key_packages_inc {
        // The nonces and commitments for each participant are generated.
        let (nonces, commitments) = frost::round1::commit(
            key_packages
                .get(&participant_identifier)
                .unwrap()
                .signing_share(),
            &mut rng,
        );
        nonces_map.insert(participant_identifier, nonces);

        // Participant with id_1 is excluded from the commitments_map so it is missing from the signing package.
        // To prevent sign() from returning an error due to incorrect number of commitments,
        // add the commitment under another unrelated participant.
        if participant_identifier == id_1 {
            commitments_map.insert(id_4, commitments);
        } else {
            commitments_map.insert(participant_identifier, commitments);
        }
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let message = "message to sign".as_bytes();
    let signing_package = SigningPackage::new(commitments_map, message);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: Participant with id_1 signs
    ////////////////////////////////////////////////////////////////////////////

    let key_package_1 = key_packages.get(&id_1).unwrap();

    let nonces_to_use = &nonces_map.get(&id_1).unwrap();

    // Each participant generates their signature share.
    let signature_share = frost::round2::sign(&signing_package, nonces_to_use, key_package_1);

    assert_eq!(signature_share, Err(Error::MissingCommitment))
}

/// Checks the signer's commitment is valid
pub fn check_sign_with_incorrect_commitments<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;
    let (shares, _pubkeys) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();

    // Verifies the secret shares from the dealer
    let mut key_packages: BTreeMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> =
        BTreeMap::new();

    for (k, v) in shares {
        let key_package = frost::keys::KeyPackage::try_from(v).unwrap();
        key_packages.insert(k, key_package);
    }

    let mut commitments_map: BTreeMap<frost::Identifier<C>, frost::round1::SigningCommitments<C>> =
        BTreeMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    let id_1 = Identifier::<C>::try_from(1).unwrap();
    let id_2 = Identifier::<C>::try_from(2).unwrap();
    let id_3 = Identifier::<C>::try_from(3).unwrap();
    // let key_packages_inc = vec![id_1, id_2, id_3];

    let (_nonces_1, commitments_1) =
        frost::round1::commit(key_packages[&id_1].signing_share(), &mut rng);

    let (_nonces_2, commitments_2) =
        frost::round1::commit(key_packages[&id_2].signing_share(), &mut rng);

    let (nonces_3, _commitments_3) =
        frost::round1::commit(key_packages[&id_3].signing_share(), &mut rng);

    commitments_map.insert(id_1, commitments_1);
    commitments_map.insert(id_2, commitments_2);
    // Invalid commitment for id_3
    commitments_map.insert(id_3, commitments_1);

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let message = "message to sign".as_bytes();
    let signing_package = SigningPackage::new(commitments_map, message);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: Participant with id_3 signs
    ////////////////////////////////////////////////////////////////////////////

    let key_package_3 = key_packages.get(&id_3).unwrap();

    // Each participant generates their signature share.
    let signature_share = frost::round2::sign(&signing_package, &nonces_3, key_package_3);

    assert!(signature_share.is_err());
    assert!(signature_share == Err(Error::IncorrectCommitment))
}

// Checks the verifying shares are valid
//
// NOTE: If the last verifying share is invalid this test will not detect this.
// The test is intended for ensuring the correct calculation of verifying shares
// which is covered in this test
fn check_verifying_shares<C: Ciphersuite>(
    pubkeys: PublicKeyPackage<C>,
    signing_package: SigningPackage<C>,
    mut signature_shares: BTreeMap<Identifier<C>, SignatureShare<C>>,
) {
    let one = <<C as Ciphersuite>::Group as Group>::Field::one();

    // Corrupt last share
    let id = *signature_shares.keys().last().unwrap();
    *signature_shares.get_mut(&id).unwrap() =
        SignatureShare::new(signature_shares[&id].to_scalar() + one);

    let e = frost::aggregate(&signing_package, &signature_shares, &pubkeys).unwrap_err();
    assert_eq!(e.culprits(), vec![id]);
    assert_eq!(e, Error::InvalidSignatureShare { culprits: vec![id] });
}

// Checks if `verify_signature_share()` works correctly.
fn check_verify_signature_share<C: Ciphersuite>(
    pubkeys: &PublicKeyPackage<C>,
    signing_package: &SigningPackage<C>,
    signature_shares: &BTreeMap<Identifier<C>, SignatureShare<C>>,
) {
    for (identifier, signature_share) in signature_shares {
        frost::verify_signature_share(
            *identifier,
            pubkeys.verifying_shares().get(identifier).unwrap(),
            signature_share,
            signing_package,
            pubkeys.verifying_key(),
        )
        .expect("should pass");
    }

    for (identifier, signature_share) in signature_shares {
        let one = <<C as Ciphersuite>::Group as Group>::Field::one();
        // Corrupt  share
        let signature_share = SignatureShare::new(signature_share.to_scalar() + one);

        frost::verify_signature_share(
            *identifier,
            pubkeys.verifying_shares().get(identifier).unwrap(),
            &signature_share,
            signing_package,
            pubkeys.verifying_key(),
        )
        .expect_err("should have failed");
    }
}

/// Test FROST signing in an async context.
/// The ultimate goal of the test is to ensure that types are Send + Sync.
pub async fn async_check_sign<C: Ciphersuite, R: RngCore + CryptoRng + 'static + Send + Sync>(
    mut rng: R,
) {
    tokio::spawn(async move {
        let max_signers = 5;
        let min_signers = 3;
        let (shares, pubkey_package) = frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )
        .unwrap();

        // The test is sprinkled with await points to ensure that types that
        // cross them are Send + Sync.
        tokio::time::sleep(core::time::Duration::from_millis(1)).await;

        // Verifies the secret shares from the dealer
        let key_packages: BTreeMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> = shares
            .into_iter()
            .map(|(k, v)| (k, frost::keys::KeyPackage::try_from(v).unwrap()))
            .collect();

        tokio::time::sleep(core::time::Duration::from_millis(1)).await;

        let mut nonces_map: BTreeMap<frost::Identifier<C>, frost::round1::SigningNonces<C>> =
            BTreeMap::new();
        let mut commitments_map: BTreeMap<
            frost::Identifier<C>,
            frost::round1::SigningCommitments<C>,
        > = BTreeMap::new();

        for participant_identifier in key_packages.keys().take(min_signers as usize).cloned() {
            // Generate one (1) nonce and one SigningCommitments instance for each
            // participant, up to _min_signers_.
            let (nonces, commitments) = frost::round1::commit(
                key_packages
                    .get(&participant_identifier)
                    .unwrap()
                    .signing_share(),
                &mut rng,
            );
            tokio::time::sleep(core::time::Duration::from_millis(1)).await;
            nonces_map.insert(participant_identifier, nonces);
            commitments_map.insert(participant_identifier, commitments);
        }

        let mut signature_shares = BTreeMap::new();
        let message = "message to sign".as_bytes();
        let signing_package = SigningPackage::new(commitments_map, message);

        for participant_identifier in nonces_map.keys() {
            let key_package = key_packages.get(participant_identifier).unwrap();
            let nonces_to_use = nonces_map.get(participant_identifier).unwrap();
            let signature_share =
                frost::round2::sign(&signing_package, nonces_to_use, key_package).unwrap();
            tokio::time::sleep(core::time::Duration::from_millis(1)).await;
            signature_shares.insert(*participant_identifier, signature_share);
        }

        let group_signature =
            frost::aggregate(&signing_package, &signature_shares, &pubkey_package).unwrap();
        tokio::time::sleep(core::time::Duration::from_millis(1)).await;

        pubkey_package
            .verifying_key
            .verify(message, &group_signature)
            .unwrap();
        tokio::time::sleep(core::time::Duration::from_millis(1)).await;

        for (participant_identifier, _) in nonces_map.clone() {
            let key_package = key_packages.get(&participant_identifier).unwrap();
            key_package
                .verifying_key
                .verify(message, &group_signature)
                .unwrap();
            tokio::time::sleep(core::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

/// Test FROST signing using COCKTAIL-DKG for key generation with a Ciphersuite.
pub fn check_sign_with_cocktail_dkg<C: CocktailCiphersuite + PartialEq, R: RngCore + CryptoRng>(
    mut rng: R,
) -> (Vec<u8>, Signature<C>, VerifyingKey<C>)
where
    C::Group: core::cmp::PartialEq,
{
    let max_signers: u16 = 3;
    let min_signers: u16 = 2;

    // Generate static signing keys for all participants.
    let mut static_keys: BTreeMap<Identifier<C>, SigningKey<C>> = BTreeMap::new();
    let mut participants: BTreeMap<Identifier<C>, VerifyingKey<C>> = BTreeMap::new();
    for i in 1..=max_signers {
        let id = Identifier::<C>::try_from(i).expect("should be nonzero");
        let sk = SigningKey::<C>::new(&mut rng);
        let vk = VerifyingKey::from(&sk);
        static_keys.insert(id, sk);
        participants.insert(id, vk);
    }

    let context = b"test-cocktail-dkg";
    let extension = b"";

    ////////////////////////////////////////////////////////////////////////////
    // COCKTAIL-DKG Round 1
    ////////////////////////////////////////////////////////////////////////////

    let mut round1_secret_packages: BTreeMap<
        Identifier<C>,
        frost::keys::cocktail_dkg::round1::SecretPackage<C>,
    > = BTreeMap::new();
    let mut received_round1_packages: BTreeMap<
        Identifier<C>,
        BTreeMap<Identifier<C>, frost::keys::cocktail_dkg::round1::Package<C>>,
    > = BTreeMap::new();

    for (&id, sk) in &static_keys {
        let (secret_pkg, pkg) = frost::keys::cocktail_dkg::part1(
            id,
            max_signers,
            min_signers,
            sk,
            &participants,
            context,
            &BTreeMap::new(),
            &mut rng,
        )
        .unwrap();
        round1_secret_packages.insert(id, secret_pkg);
        for &receiver_id in participants.keys() {
            if receiver_id != id {
                received_round1_packages
                    .entry(receiver_id)
                    .or_default()
                    .insert(id, pkg.clone());
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // COCKTAIL-DKG Round 2
    ////////////////////////////////////////////////////////////////////////////

    let mut round2_secret_packages: BTreeMap<
        Identifier<C>,
        frost::keys::cocktail_dkg::round2::SecretPackage<C>,
    > = BTreeMap::new();
    let mut received_round2_packages: BTreeMap<
        Identifier<C>,
        BTreeMap<Identifier<C>, frost::keys::cocktail_dkg::round2::Package<C>>,
    > = BTreeMap::new();

    for (&id, sk) in &static_keys {
        let secret_pkg = round1_secret_packages.remove(&id).unwrap();
        let round1_packages = &received_round1_packages[&id];
        let (r2_secret, r2_pkg, _received_payloads) = frost::keys::cocktail_dkg::part2(
            secret_pkg,
            round1_packages,
            sk,
            &participants,
            context,
            extension,
            &mut rng,
        )
        .unwrap();
        round2_secret_packages.insert(id, r2_secret);
        for &receiver_id in participants.keys() {
            received_round2_packages
                .entry(receiver_id)
                .or_default()
                .insert(id, r2_pkg.clone());
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // COCKTAIL-DKG Round 3 (CertEq)
    ////////////////////////////////////////////////////////////////////////////

    let mut key_packages = BTreeMap::new();
    let mut pubkey_packages = BTreeMap::new();

    for &id in static_keys.keys() {
        let r2_secret = &round2_secret_packages[&id];
        let round2_packages = &received_round2_packages[&id];
        let (key_pkg, pubkey_pkg, _transcript, _cert) =
            frost::keys::cocktail_dkg::part3(r2_secret, round2_packages).unwrap();
        key_packages.insert(id, key_pkg);
        pubkey_packages.insert(id, pubkey_pkg);
    }

    // All participants must agree on the same group public key.
    let first_pubkey = pubkey_packages.values().next().unwrap().clone();
    for pubkey_pkg in pubkey_packages.values() {
        assert_eq!(first_pubkey.verifying_key(), pubkey_pkg.verifying_key());
    }

    // Use the DKG-derived key packages to run a FROST signing session.
    check_sign(min_signers, key_packages, rng, first_pubkey).unwrap()
}

/// Counter-based deterministic RNG for COCKTAIL-DKG test vectors.
///
/// Each block is: `hash_fn(seed || cs_id || uint32_le(t) || uint32_le(n) || label || uint64_le(counter))`
struct CounterDrng<'a> {
    seed: Vec<u8>,
    cs_id: Vec<u8>,
    t: u32,
    n: u32,
    label: Vec<u8>,
    counter: u64,
    hash_fn: &'a dyn Fn(&[u8]) -> Vec<u8>,
    buf: Vec<u8>,
    buf_pos: usize,
}

impl<'a> CounterDrng<'a> {
    fn new(
        seed: &[u8],
        cs_id: &[u8],
        t: u32,
        n: u32,
        participant: u32,
        hash_fn: &'a dyn Fn(&[u8]) -> Vec<u8>,
    ) -> Self {
        Self {
            seed: seed.to_vec(),
            cs_id: cs_id.to_vec(),
            t,
            n,
            label: format!("round1_participant_{}", participant).into_bytes(),
            counter: 0,
            hash_fn,
            buf: Vec::new(),
            buf_pos: 0,
        }
    }

    fn refill(&mut self) {
        let mut input = Vec::new();
        input.extend_from_slice(&self.seed);
        input.extend_from_slice(&self.cs_id);
        input.extend_from_slice(&self.t.to_le_bytes());
        input.extend_from_slice(&self.n.to_le_bytes());
        input.extend_from_slice(&self.label);
        input.extend_from_slice(&self.counter.to_le_bytes());
        self.buf = (self.hash_fn)(&input);
        self.buf_pos = 0;
        self.counter += 1;
    }
}

impl RngCore for CounterDrng<'_> {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut pos = 0;
        while pos < dest.len() {
            if self.buf_pos == self.buf.len() {
                self.refill();
            }
            let available = self.buf.len() - self.buf_pos;
            let needed = dest.len() - pos;
            let to_copy = available.min(needed);
            dest[pos..pos + to_copy]
                .copy_from_slice(&self.buf[self.buf_pos..self.buf_pos + to_copy]);
            self.buf_pos += to_copy;
            pos += to_copy;
        }
    }

    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for CounterDrng<'_> {}

/// Test COCKTAIL-DKG protocol against JSON test vectors.
///
/// - `json`: JSON test vector content (use `include_str!` in the caller).
/// - `hash_fn`: Hash/XOF function used as a counter-based RNG for test vectors.
///   E.g. `|data| Sha256::digest(data).to_vec()`.
/// - `compare_encrypted_shares`: Whether to compare encrypted shares against the vectors.
///   Set `false` when the ciphersuite AEAD differs from the reference
///   (e.g. P-256/secp256k1 spec requires XAES-256-GCM, not XChaCha20Poly1305).
/// - `check_recovery`: Whether to test the `recovery` section of the vector.
///   Set `false` when the encrypted share format is incompatible with the reference.
pub fn check_cocktail_dkg_test_vectors<C, H>(
    json: &str,
    hash_fn: H,
    compare_encrypted_shares: bool,
    check_recovery: bool,
) where
    C: CocktailCiphersuite,
    H: Fn(&[u8]) -> Vec<u8>,
{
    let file: serde_json::Value = serde_json::from_str(json.trim()).unwrap();
    let seed = hex::decode(file["seed"].as_str().unwrap()).unwrap();
    let cs_id = file["ciphersuite"].as_str().unwrap().as_bytes().to_vec();
    let hash_fn_ref: &dyn Fn(&[u8]) -> Vec<u8> = &hash_fn;

    for vector in file["vectors"].as_array().unwrap().iter() {
        let n = vector["n"].as_u64().unwrap() as u32;
        let t = vector["t"].as_u64().unwrap() as u32;
        let context = hex::decode(vector["context"].as_str().unwrap()).unwrap();

        let static_secret_key_bytes: Vec<Vec<u8>> = vector["config"]["static_secret_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
            .collect();

        let expected_ephemeral_pubs: Vec<Vec<u8>> = vector["round1"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| hex::decode(p["ephemeral_public_key"].as_str().unwrap()).unwrap())
            .collect();

        let expected_group_public_key =
            hex::decode(vector["group_public_key"].as_str().unwrap()).unwrap();

        let expected_shares: Vec<Vec<u8>> = vector["round2"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| hex::decode(p["secret_share"].as_str().unwrap()).unwrap())
            .collect();

        let expected_verification_shares: Vec<Vec<u8>> = vector["round2"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| hex::decode(p["verification_share"].as_str().unwrap()).unwrap())
            .collect();

        let identifiers: Vec<Identifier<C>> = (1..=n as u16)
            .map(|i| i.try_into().unwrap())
            .collect();

        let mut static_keys: BTreeMap<Identifier<C>, SigningKey<C>> = BTreeMap::new();
        let mut participants: BTreeMap<Identifier<C>, VerifyingKey<C>> = BTreeMap::new();
        for (id, key_bytes) in identifiers.iter().zip(static_secret_key_bytes.iter()) {
            // Try direct deserialization first; if it fails (wrong length), append one zero
            // byte and retry. This handles ed448 where JSON stores 56-byte raw scalars but
            // the ciphersuite uses 57-byte RFC 8032 format (trailing 0x00).
            let sk = SigningKey::<C>::deserialize(key_bytes).unwrap_or_else(|_| {
                let mut padded = key_bytes.clone();
                padded.push(0);
                SigningKey::<C>::deserialize(&padded).unwrap()
            });
            let vk = VerifyingKey::from(&sk);
            static_keys.insert(*id, sk);
            participants.insert(*id, vk);
        }

        let extension = b"";

        // Round 1
        let mut round1_secret_packages: BTreeMap<
            Identifier<C>,
            frost::keys::cocktail_dkg::round1::SecretPackage<C>,
        > = BTreeMap::new();
        let mut received_round1_packages: BTreeMap<
            Identifier<C>,
            BTreeMap<Identifier<C>, frost::keys::cocktail_dkg::round1::Package<C>>,
        > = BTreeMap::new();

        for (idx, (&id, sk)) in static_keys.iter().enumerate() {
            let mut rng = CounterDrng::new(&seed, &cs_id, t, n, (idx + 1) as u32, hash_fn_ref);
            let (secret_pkg, pkg) = frost::keys::cocktail_dkg::part1(
                id,
                n as u16,
                t as u16,
                sk,
                &participants,
                &context,
                &BTreeMap::new(),
                &mut rng,
            )
            .unwrap();

            let round1_tv = &vector["round1"][idx];

            assert_eq!(
                <<C as Ciphersuite>::Group>::serialize(pkg.ephemeral_pub())
                    .unwrap()
                    .as_ref(),
                expected_ephemeral_pubs[idx].as_slice(),
                "participant {} ephemeral public key mismatch",
                idx + 1
            );

            let expected_commitment: Vec<Vec<u8>> = round1_tv["vss_commitment"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
                .collect();
            assert_eq!(
                pkg.commitment().serialize().unwrap(),
                expected_commitment,
                "participant {} VSS commitment mismatch",
                idx + 1
            );

            if compare_encrypted_shares {
                let expected_enc_shares: Vec<Vec<u8>> = round1_tv["encrypted_shares"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
                    .collect();
                for (j, &receiver_id) in identifiers.iter().enumerate() {
                    let actual = &pkg.encrypted_shares()[&receiver_id];
                    assert_eq!(
                        actual.as_slice(),
                        expected_enc_shares[j].as_slice(),
                        "participant {} encrypted share for receiver {} mismatch",
                        idx + 1,
                        j + 1
                    );
                }
            }

            round1_secret_packages.insert(id, secret_pkg);
            for &receiver_id in participants.keys() {
                if receiver_id != id {
                    received_round1_packages
                        .entry(receiver_id)
                        .or_default()
                        .insert(id, pkg.clone());
                }
            }
        }

        // Round 2
        let mut round2_secret_packages: BTreeMap<
            Identifier<C>,
            frost::keys::cocktail_dkg::round2::SecretPackage<C>,
        > = BTreeMap::new();
        let mut received_round2_packages: BTreeMap<
            Identifier<C>,
            BTreeMap<Identifier<C>, frost::keys::cocktail_dkg::round2::Package<C>>,
        > = BTreeMap::new();

        for (&id, sk) in static_keys.iter() {
            let secret_pkg = round1_secret_packages.remove(&id).unwrap();
            let round1_packages = &received_round1_packages[&id];
            // Use participant 0 as a sentinel RNG for part2 (transcript Schnorr signing).
            // This randomness is not verified against test vectors.
            let mut rng2 = CounterDrng::new(&seed, &cs_id, t, n, 0, hash_fn_ref);
            let (r2_secret, r2_pkg, _received_payloads) = frost::keys::cocktail_dkg::part2(
                secret_pkg,
                round1_packages,
                sk,
                &participants,
                &context,
                extension,
                &mut rng2,
            )
            .unwrap();

            round2_secret_packages.insert(id, r2_secret);
            for &receiver_id in participants.keys() {
                received_round2_packages
                    .entry(receiver_id)
                    .or_default()
                    .insert(id, r2_pkg.clone());
            }
        }

        // Round 3
        let mut transcript_for_recovery: Vec<u8> = Vec::new();
        let mut cert_for_recovery: BTreeMap<Identifier<C>, Signature<C>> = BTreeMap::new();

        for (idx, (&id, _)) in static_keys.iter().enumerate() {
            let r2_secret = &round2_secret_packages[&id];
            let round2_packages = &received_round2_packages[&id];
            let (key_pkg, pubkey_pkg, transcript, cert) =
                frost::keys::cocktail_dkg::part3(r2_secret, round2_packages).unwrap();

            if idx == 0 && check_recovery {
                transcript_for_recovery = transcript;
                cert_for_recovery = cert;
            }

            assert_eq!(
                pubkey_pkg.verifying_key().serialize().unwrap().as_slice(),
                expected_group_public_key.as_slice(),
                "participant {} group public key mismatch",
                idx + 1
            );

            // Compare only the prefix when JSON bytes are fewer than the serialized length.
            // Handles ed448 (56-byte JSON raw scalar vs 57-byte RFC 8032 format).
            let serialized_share = key_pkg.signing_share().serialize();
            let expected = expected_shares[idx].as_slice();
            let cmp_len = expected.len().min(serialized_share.len());
            assert_eq!(
                &serialized_share[..cmp_len],
                &expected[..cmp_len],
                "participant {} secret share mismatch",
                idx + 1
            );

            assert_eq!(
                pubkey_pkg
                    .verifying_shares()
                    .get(&id)
                    .unwrap()
                    .serialize()
                    .unwrap()
                    .as_slice(),
                expected_verification_shares[idx].as_slice(),
                "participant {} verification share mismatch",
                idx + 1
            );
        }

        // Recovery
        if check_recovery {
            if let Some(recovery) = vector.get("recovery") {
                let recovery_id = recovery["participant_id"].as_u64().unwrap() as u16;
                let recovery_identifier = Identifier::<C>::try_from(recovery_id).unwrap();
                let recovery_sk = static_keys.get(&recovery_identifier).unwrap();

                let ciphertexts_json = recovery["ciphertexts"].as_array().unwrap();
                let mut recovery_ciphertexts: BTreeMap<Identifier<C>, Vec<u8>> = BTreeMap::new();
                for (j_idx, ct) in ciphertexts_json.iter().enumerate() {
                    let sender_id = Identifier::<C>::try_from((j_idx + 1) as u16).unwrap();
                    recovery_ciphertexts
                        .insert(sender_id, hex::decode(ct.as_str().unwrap()).unwrap());
                }

                let expected_recovered_share =
                    hex::decode(recovery["recovered_secret_share"].as_str().unwrap()).unwrap();
                let expected_recovered_vshare = hex::decode(
                    recovery["recovered_verification_share"].as_str().unwrap(),
                )
                .unwrap();

                let (recovered_key_pkg, recovered_pubkey_pkg) =
                    frost::keys::cocktail_dkg::recover(
                        recovery_sk,
                        &transcript_for_recovery,
                        &cert_for_recovery,
                        &recovery_ciphertexts,
                    )
                    .unwrap();

                assert_eq!(
                    recovered_key_pkg.signing_share().serialize().as_slice(),
                    expected_recovered_share.as_slice(),
                    "recovered secret share mismatch"
                );
                assert_eq!(
                    recovered_pubkey_pkg
                        .verifying_shares()
                        .get(&recovery_identifier)
                        .unwrap()
                        .serialize()
                        .unwrap()
                        .as_slice(),
                    expected_recovered_vshare.as_slice(),
                    "recovered verification share mismatch"
                );
            }
        }
    }
}
