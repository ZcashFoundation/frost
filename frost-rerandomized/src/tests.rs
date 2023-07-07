//! Ciphersuite-generic test functions for re-randomized FROST.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{frost_core::frost, frost_core::Ciphersuite, RandomizedParams};
use frost_core::{
    frost::{
        compute_lagrange_coefficient,
        keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare},
    },
    tests::ciphersuite_generic::check_sign,
    Field, Group, Signature, SigningKey, VerifyingKey,
};
use rand_core::{CryptoRng, RngCore};

/// Check if manual rerandomization works
pub fn check_rerandomization<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    let secret = SigningKey::<C>::new(&mut rng);

    let max_signers = 5;
    let min_signers = 3;
    let (shares, pubkeys) = frost::keys::split(
        &secret,
        max_signers,
        min_signers,
        frost::keys::IdentifierList::<C>::Default,
        &mut rng,
    )
    .unwrap();

    let key_packages: HashMap<_, _> = shares
        .iter()
        .map(|(i, s)| (*i, frost::keys::KeyPackage::try_from(s.clone()).unwrap()))
        .collect();

    let alpha_prime = <<C::Group as Group>::Field as Field>::random(&mut rng);

    let xs: BTreeSet<frost::Identifier<_>> = key_packages
        .keys()
        .take(min_signers as usize)
        .cloned()
        .collect();
    let lagrange_sum = key_packages
        .keys()
        .take(min_signers as usize)
        .map(|i| compute_lagrange_coefficient(&xs, None, *i).unwrap())
        .reduce(|acc, e| acc + e)
        .unwrap();
    let alpha = alpha_prime * <<C::Group as Group>::Field as Field>::invert(&lagrange_sum).unwrap();

    let randomizer_point = <C::Group as Group>::generator() * alpha_prime;
    let group_public_point = pubkeys.group_public().to_element();
    let randomized_group_public_point = group_public_point + randomizer_point;
    let randomized_pubkey = VerifyingKey::<C>::new(randomized_group_public_point);

    let mut verifying_shares = pubkeys.signer_pubkeys().clone();
    let mut randomized_key_packages = key_packages.clone();
    for (identifier, key_package) in randomized_key_packages.iter_mut() {
        let randomizer_point = <C::Group as Group>::generator() * alpha;
        let verifying_share = verifying_shares.get_mut(identifier).unwrap();
        let randomized_verifying_share =
            VerifyingShare::<C>::new(verifying_share.to_element() + randomizer_point);
        *verifying_share = randomized_verifying_share;

        let share = key_package.secret_share();
        let randomized_value = SigningShare::new(share.to_scalar() + alpha);
        let randomized_key_package = KeyPackage::new(
            *identifier,
            randomized_value,
            randomized_verifying_share,
            randomized_pubkey,
        );
        *key_package = randomized_key_package;
    }

    let randomized_secret = SigningKey::<C>::from_scalar(secret.to_scalar() + alpha_prime);

    let randomized_pubkeys = PublicKeyPackage::new(verifying_shares, randomized_pubkey);

    assert_eq!(
        frost::keys::reconstruct::<C>(&key_packages.values().cloned().collect::<Vec<_>>())
            .unwrap()
            .serialize()
            .as_ref(),
        secret.serialize().as_ref()
    );

    assert_eq!(
        frost::keys::reconstruct::<C>(
            &randomized_key_packages
                .values()
                .take(min_signers as usize)
                .cloned()
                .collect::<Vec<_>>()
        )
        .unwrap()
        .serialize()
        .as_ref(),
        randomized_secret.serialize().as_ref()
    );

    let signature = secret.sign(&mut rng, "hello world".as_bytes());
    assert!(pubkeys
        .group_public()
        .verify("hello world".as_bytes(), &signature)
        .is_ok());

    let signature = randomized_secret.sign(&mut rng, "hello world".as_bytes());
    assert!(randomized_pubkey
        .verify("hello world".as_bytes(), &signature)
        .is_ok());

    check_sign(
        min_signers,
        randomized_key_packages,
        &mut rng,
        randomized_pubkeys,
    );
}

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
    let (shares, pubkeys) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();

    // Verifies the secret shares from the dealer
    let mut key_packages: HashMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> =
        HashMap::new();

    for (k, v) in shares {
        key_packages.insert(k, frost::keys::KeyPackage::try_from(v).unwrap());
    }

    let mut nonces: HashMap<frost::Identifier<C>, frost::round1::SigningNonces<C>> = HashMap::new();
    let mut commitments: BTreeMap<frost::Identifier<C>, frost::round1::SigningCommitments<C>> =
        BTreeMap::new();

    let participants: BTreeSet<_> = key_packages.keys().cloned().collect();

    check_from_randomizer(&pubkeys, &mut rng);
    let randomizer_params =
        RandomizedParams::new(pubkeys.group_public(), &participants, &mut rng).unwrap();
    let randomizer = randomizer_params.randomizer();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    for participant_index in 1..(min_signers + 1) {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _min_signers_.
        let (nonce, commitment) = frost::round1::commit(
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
    let mut signature_shares: HashMap<frost::Identifier<_>, frost::round2::SignatureShare<_>> =
        HashMap::new();
    let message = "message to sign".as_bytes();
    let signing_package = frost::SigningPackage::new(commitments, message);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    for participant_identifier in nonces.keys() {
        let key_package = key_packages.get(participant_identifier).unwrap();

        let nonces_to_use = &nonces.get(participant_identifier).unwrap();

        // Each participant generates their signature share.
        let signature_share =
            crate::sign(&signing_package, nonces_to_use, key_package, randomizer).unwrap();
        signature_shares.insert(*participant_identifier, signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate (also verifies the signature shares)
    let group_signature_res = crate::aggregate(
        &signing_package,
        &signature_shares,
        &pubkeys,
        &randomizer_params,
    );

    assert!(group_signature_res.is_ok());

    let group_signature = group_signature_res.unwrap();

    // Check that the threshold signature can be verified by the randomized group public
    // key (the verification key).
    assert!(randomizer_params
        .randomized_verifying_key()
        .verify(message, &group_signature)
        .is_ok());

    // Note that key_package.group_public can't be used to verify the signature
    // since those are non-randomized.

    (
        message.to_owned(),
        group_signature,
        *randomizer_params.randomized_verifying_key(),
    )
}

fn check_from_randomizer<C: Ciphersuite, R: RngCore + CryptoRng>(
    pubkeys: &frost::keys::PublicKeyPackage<C>,
    mut rng: &mut R,
) {
    let participants: BTreeSet<_> = pubkeys.signer_pubkeys().keys().cloned().collect();

    let randomizer = <<C::Group as Group>::Field as Field>::random(&mut rng);

    let randomizer_params =
        RandomizedParams::from_randomizer(pubkeys.group_public(), &participants, &randomizer)
            .unwrap();

    assert!(*randomizer_params.randomizer() == randomizer);
}
