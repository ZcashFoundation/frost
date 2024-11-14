use std::{error::Error, vec};

use k256::elliptic_curve::point::AffineCoordinates;
use k256::ProjectivePoint;
use keys::Tweak;
use sha2::{Digest, Sha256};

use frost_secp256k1_tr::*;

mod helpers;

#[test]
fn check_tweaked_sign_with_dealer() -> Result<(), Box<dyn Error>> {
    use frost_secp256k1_tr as frost;
    use rand::thread_rng;
    use std::collections::BTreeMap;

    let merkle_root: Vec<u8> = vec![12; 32];

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

    let pubkey_package_tweaked = pubkey_package.clone().tweak(Some(&merkle_root));
    pubkey_package_tweaked
        .verifying_key()
        .verify(message, &group_signature)
        .expect("signature should be valid for tweaked pubkey_package");

    helpers::verify_signature(
        message,
        &group_signature,
        pubkey_package_tweaked.verifying_key(),
    );

    // Confirm the internal (untweaked) group key can be provided to access
    // script spending paths under the output (tweaked) group key.
    let (expected_parity, expected_tr_output_pubkey) = taproot_tweak_pubkey(
        pubkey_package
            .verifying_key()
            .to_element()
            .to_affine()
            .x()
            .into(),
        &merkle_root,
    );

    let tr_output_point = pubkey_package_tweaked
        .verifying_key()
        .to_element()
        .to_affine();

    let tr_output_pubkey: [u8; 32] = tr_output_point.x().into();
    let tr_output_parity: bool = tr_output_point.y_is_odd().into();

    assert_eq!(
        tr_output_pubkey, expected_tr_output_pubkey,
        "taproot output pubkey does not match"
    );

    assert_eq!(
        tr_output_parity, expected_parity,
        "taproot output pubkey parity bit does not match"
    );

    Ok(())
}

/// Emulates the BIP341 helper function:
///
///   def taproot_tweak_pubkey(pubkey, h):
///       t = int_from_bytes(tagged_hash("TapTweak", pubkey + h))
///       if t >= SECP256K1_ORDER:
///           raise ValueError
///       P = lift_x(int_from_bytes(pubkey))
///       if P is None:
///           raise ValueError
///       Q = point_add(P, point_mul(G, t))
///       return 0 if has_even_y(Q) else 1, bytes_from_int(x(Q))
///
fn taproot_tweak_pubkey(pubkey: [u8; 32], merkle_root: &[u8]) -> (bool, [u8; 32]) {
    let prefix = Sha256::digest(b"TapTweak");
    let tweak_hash = Sha256::new()
        .chain_update(prefix)
        .chain_update(prefix)
        .chain_update(pubkey)
        .chain_update(merkle_root)
        .finalize();
    let t = k256::Scalar::from(
        k256::elliptic_curve::ScalarPrimitive::new(k256::U256::from_be_slice(&tweak_hash)).unwrap(),
    );

    let mut pubkey_even_bytes = [0x02; 33];
    pubkey_even_bytes[1..].copy_from_slice(&pubkey);
    let pubkey_even = Secp256K1Group::deserialize(&pubkey_even_bytes).unwrap();

    let tr_output_key = (pubkey_even + ProjectivePoint::GENERATOR * t).to_affine();
    (tr_output_key.y_is_odd().into(), tr_output_key.x().into())
}
