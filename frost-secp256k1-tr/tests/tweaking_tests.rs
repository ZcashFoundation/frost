use std::{error::Error, vec};

use frost_secp256k1_tr::*;
use keys::Tweak;

mod helpers;

#[test]
fn check_tweaked_sign_with_dealer() -> Result<(), Box<dyn Error>> {
    use frost_secp256k1_tr as frost;
    use rand::thread_rng;
    use std::collections::BTreeMap;

    let merkle_root: Vec<u8> = vec![];

    let mut rng = thread_rng();
    let max_signers = 5;
    let min_signers = 3;
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;
    let mut key_packages: BTreeMap<_, _> = BTreeMap::new();
    for (identifier, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
        key_packages.insert(identifier, key_package);
    }

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    for participant_index in 1..=min_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let key_package = &key_packages[&participant_identifier];
        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);
        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    let mut signature_shares = BTreeMap::new();
    let message = "message to sign".as_bytes();
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    for participant_identifier in nonces_map.keys() {
        let key_package = &key_packages[participant_identifier];
        let nonces = &nonces_map[participant_identifier];
        let signature_share = frost::round2::sign_with_tweak(
            &signing_package,
            nonces,
            key_package,
            Some(&merkle_root),
        )?;
        signature_shares.insert(*participant_identifier, signature_share);
    }

    let group_signature = frost::aggregate_with_tweak(
        &signing_package,
        &signature_shares,
        &pubkey_package,
        Some(&merkle_root),
    )?;

    pubkey_package
        .verifying_key()
        .verify(message, &group_signature)
        .expect_err("signature should not be valid for untweaked pubkey_package");

    let pubkey_package = pubkey_package.tweak(Some(&merkle_root));
    pubkey_package
        .verifying_key()
        .verify(message, &group_signature)
        .expect("signature should be valid for tweaked pubkey_package");

    helpers::verify_signature(message, &group_signature, pubkey_package.verifying_key());

    Ok(())
}
