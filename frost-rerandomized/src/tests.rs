//! Ciphersuite-generic test functions for re-randomized FROST.

use std::collections::HashMap;

use crate::{frost_core::frost, frost_core::Ciphersuite, RandomizedParams};
use frost_core::{Field, Group, Signature, VerifyingKey};
use rand_core::{CryptoRng, RngCore};

/// Test re-randomized FROST signing with trusted dealer with a Ciphersuite.
/// Returns the signed message, generated signature, and the randomized public key
/// so that the caller can verify the signature with their own implementation.
pub fn check_randomized_sign_with_dealer<C: Ciphersuite, R: RngCore + CryptoRng>(
    mut rng: R,
) -> (Vec<u8>, Signature<C>, VerifyingKey<C>) {
    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;
    let (shares, pubkeys) =
        frost::keys::generate_with_dealer(max_signers, min_signers, &mut rng).unwrap();

    // Verifies the secret shares from the dealer
    let mut key_packages: HashMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> =
        HashMap::new();

    for (k, v) in shares {
        key_packages.insert(k, frost::keys::KeyPackage::try_from(v).unwrap());
    }

    let mut nonces: HashMap<frost::Identifier<C>, frost::round1::SigningNonces<C>> = HashMap::new();
    let mut commitments: HashMap<frost::Identifier<C>, frost::round1::SigningCommitments<C>> =
        HashMap::new();

    check_from_randomizer(&pubkeys, &mut rng);
    let randomizer_params = RandomizedParams::new(&pubkeys, &mut rng);

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    for participant_index in 1..(min_signers + 1) {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _min_signers_.
        let (nonce, commitment) = frost::round1::commit(
            participant_identifier,
            key_packages
                .get(&participant_identifier)
                .unwrap()
                .secret_share(),
            &mut rng,
        );
        nonces.insert(participant_identifier, nonce);
        commitments.insert(participant_identifier, commitment);
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares: Vec<frost::round2::SignatureShare<_>> = Vec::new();
    let message = "message to sign".as_bytes();
    let comms = commitments.clone().into_values().collect();
    let signing_package = frost::SigningPackage::new(comms, message);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    for participant_identifier in nonces.keys() {
        let key_package = key_packages.get(participant_identifier).unwrap();

        let nonces_to_use = &nonces.get(participant_identifier).unwrap();

        // Each participant generates their signature share.
        let signature_share = crate::sign(
            &signing_package,
            nonces_to_use,
            key_package,
            randomizer_params.randomizer_point(),
        )
        .unwrap();
        signature_shares.push(signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate (also verifies the signature shares)
    let group_signature_res = crate::aggregate(
        &signing_package,
        &signature_shares[..],
        &pubkeys,
        &randomizer_params,
    );

    assert!(group_signature_res.is_ok());

    let group_signature = group_signature_res.unwrap();

    // Check that the threshold signature can be verified by the randomized group public
    // key (the verification key).
    assert!(randomizer_params
        .randomized_group_public_key()
        .verify(message, &group_signature)
        .is_ok());

    // Note that key_package.group_public can't be used to verify the signature
    // since those are non-randomized.

    (
        message.to_owned(),
        group_signature,
        *randomizer_params.randomized_group_public_key(),
    )
}

fn check_from_randomizer<C: Ciphersuite, R: RngCore + CryptoRng>(
    pubkeys: &frost::keys::PublicKeyPackage<C>,
    mut rng: &mut R,
) {
    let randomizer = <<C::Group as Group>::Field as Field>::random(&mut rng);

    let randomizer_params = RandomizedParams::from_randomizer(pubkeys, randomizer);

    assert!(*randomizer_params.randomizer() == randomizer);
}
