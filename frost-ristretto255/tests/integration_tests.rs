use frost_ristretto255::*;
use lazy_static::lazy_static;
use serde_json::Value;

#[test]
fn check_zero_key_fails() {
    frost_core::tests::ciphersuite_generic::check_zero_key_fails::<Ristretto255Sha512>();
}

#[test]
fn check_sign_with_dkg() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::ciphersuite_generic::check_sign_with_dkg::<Ristretto255Sha512, _>(rng);
}

#[test]
fn check_sign_with_cocktail_dkg() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::ciphersuite_generic::check_sign_with_cocktail_dkg::<Ristretto255Sha512, _>(
        rng,
    );
}

#[test]
fn check_dkg_part1_fails_with_invalid_signers_min_signers() {
    let rng = rand::rngs::OsRng;

    let min_signers = 1;
    let max_signers = 3;
    let error = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Ristretto255Sha512,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_dkg_part1_fails_with_min_signers_greater_than_max() {
    let rng = rand::rngs::OsRng;

    let min_signers = 3;
    let max_signers = 2;
    let error: frost_core::Error<Ristretto255Sha512> = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Ristretto255Sha512,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_dkg_part1_fails_with_invalid_signers_max_signers() {
    let rng = rand::rngs::OsRng;

    let min_signers = 3;
    let max_signers = 1;
    let error = Error::InvalidMaxSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Ristretto255Sha512,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_rts() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::repairable::check_rts::<Ristretto255Sha512, _>(rng);
}

#[test]
fn check_refresh_shares_with_dealer() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::refresh::check_refresh_shares_with_dealer::<Ristretto255Sha512, _>(rng);
}

#[test]
fn check_refresh_shares_with_dealer_serialisation() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::refresh::check_refresh_shares_with_dealer_serialisation::<
        Ristretto255Sha512,
        _,
    >(rng);
}

#[test]
fn check_refresh_shares_with_dealer_fails_with_invalid_public_key_package() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::refresh::check_refresh_shares_with_dealer_fails_with_invalid_public_key_package::<
        Ristretto255Sha512,
        _,
    >(rng);
}

#[test]
fn check_refresh_shares_with_dealer_fails_with_invalid_identifier() {
    let rng = rand::rngs::OsRng;
    let identifiers = vec![
        Identifier::try_from(8).unwrap(),
        Identifier::try_from(3).unwrap(),
        Identifier::try_from(4).unwrap(),
        Identifier::try_from(6).unwrap(),
    ];
    let error = Error::UnknownIdentifier;

    frost_core::tests::refresh::check_refresh_shares_with_dealer_fails_with_invalid_signers::<
        Ristretto255Sha512,
        _,
    >(&identifiers, error, rng);
}

#[test]
fn check_refresh_shares_with_dkg() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::refresh::check_refresh_shares_with_dkg::<Ristretto255Sha512, _>(rng);
}

#[test]
fn check_refresh_shares_with_dkg_smaller_threshold() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::refresh::check_refresh_shares_with_dkg_smaller_threshold::<
        Ristretto255Sha512,
        _,
    >(rng);
}

#[test]
fn check_sign_with_dealer() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<Ristretto255Sha512, _>(rng);
}

#[test]
fn check_sign_with_dealer_fails_with_invalid_min_signers() {
    let rng = rand::rngs::OsRng;

    let min_signers = 1;
    let max_signers = 3;
    let error = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Ristretto255Sha512,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_sign_with_dealer_fails_with_min_signers_greater_than_max() {
    let rng = rand::rngs::OsRng;

    let min_signers = 3;
    let max_signers = 2;
    let error: frost_core::Error<Ristretto255Sha512> = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Ristretto255Sha512,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_sign_with_dealer_fails_with_invalid_max_signers() {
    let rng = rand::rngs::OsRng;

    let min_signers = 3;
    let max_signers = 1;
    let error = Error::InvalidMaxSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Ristretto255Sha512,
        _,
    >(min_signers, max_signers, error, rng);
}

/// This is testing that Shamir's secret sharing to compute and arbitrary
/// value is working.
#[test]
fn check_share_generation_ristretto255_sha512() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::ciphersuite_generic::check_share_generation::<Ristretto255Sha512, _>(rng);
}

#[test]
fn check_share_generation_fails_with_invalid_min_signers() {
    let rng = rand::rngs::OsRng;

    let min_signers = 0;
    let max_signers = 3;
    let error = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_share_generation_fails_with_invalid_signers::<
        Ristretto255Sha512,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_share_generation_fails_with_min_signers_greater_than_max() {
    let rng = rand::rngs::OsRng;

    let min_signers = 3;
    let max_signers = 2;
    let error: frost_core::Error<Ristretto255Sha512> = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_share_generation_fails_with_invalid_signers::<
        Ristretto255Sha512,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_share_generation_fails_with_invalid_max_signers() {
    let rng = rand::rngs::OsRng;

    let min_signers = 3;
    let max_signers = 0;
    let error = Error::InvalidMaxSigners;

    frost_core::tests::ciphersuite_generic::check_share_generation_fails_with_invalid_signers::<
        Ristretto255Sha512,
        _,
    >(min_signers, max_signers, error, rng);
}

lazy_static! {
    pub static ref VECTORS: Value =
        serde_json::from_str(include_str!("../tests/helpers/vectors.json").trim())
            .expect("Test vector is valid JSON");
    pub static ref VECTORS_BIG_IDENTIFIER: Value =
        serde_json::from_str(include_str!("../tests/helpers/vectors-big-identifier.json").trim())
            .expect("Test vector is valid JSON");
    pub static ref VECTORS_DKG: Value =
        serde_json::from_str(include_str!("../tests/helpers/vectors_dkg.json").trim())
            .expect("Test vector is valid JSON");
}

#[test]
fn check_sign_with_test_vectors() {
    frost_core::tests::vectors::check_sign_with_test_vectors::<Ristretto255Sha512>(&VECTORS);
}

#[test]
fn check_sign_with_test_vectors_dkg() {
    frost_core::tests::vectors_dkg::check_dkg_keygen::<Ristretto255Sha512>(&VECTORS_DKG);
}

#[test]
fn check_sign_with_test_vectors_with_big_identifiers() {
    frost_core::tests::vectors::check_sign_with_test_vectors::<Ristretto255Sha512>(
        &VECTORS_BIG_IDENTIFIER,
    );
}

#[test]
fn check_error_culprit() {
    frost_core::tests::ciphersuite_generic::check_error_culprit::<Ristretto255Sha512>();
}

#[test]
fn check_identifier_derivation() {
    frost_core::tests::ciphersuite_generic::check_identifier_derivation::<Ristretto255Sha512>();
}

// Explicit test which is used in a documentation snippet
#[test]
#[allow(unused_variables)]
fn check_identifier_generation() -> Result<(), Error> {
    // ANCHOR: dkg_identifier
    let participant_identifier = Identifier::try_from(7u16)?;
    let participant_identifier = Identifier::derive("alice@example.com".as_bytes())?;
    // ANCHOR_END: dkg_identifier
    Ok(())
}

#[test]
fn check_sign_with_dealer_and_identifiers() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_and_identifiers::<
        Ristretto255Sha512,
        _,
    >(rng);
}

#[test]
fn check_sign_with_missing_identifier() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::ciphersuite_generic::check_sign_with_missing_identifier::<
        Ristretto255Sha512,
        _,
    >(rng);
}

#[test]
fn check_sign_with_incorrect_commitments() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::ciphersuite_generic::check_sign_with_incorrect_commitments::<
        Ristretto255Sha512,
        _,
    >(rng);
}

#[tokio::test]
async fn check_async_sign_with_dealer() {
    tokio::spawn(async {
        let rng = rand::rngs::OsRng;
        frost_core::tests::ciphersuite_generic::async_check_sign::<Ristretto255Sha512, _>(rng)
            .await;
    })
    .await
    .unwrap();
}

/// Test COCKTAIL-DKG with the 2-of-3 test vectors from the cocktail-dkg.md spec.
///
/// The static secret keys and expected outputs are from Appendix B of the spec:
/// <https://c2sp.org/cocktail-dkg>
///
/// NOTE: This test is currently ignored because the spec's "Round 1 RNG stream"
/// derivation uses an exact DRNG that is only fully specified in the CCTV JSON
/// test vectors (<https://github.com/C2SP/CCTV/tree/main/cocktail-dkg>). Once
/// those vectors are integrated, this test can be updated to use the correct
/// DRNG seeding and the `#[ignore]` attribute removed.
#[test]
#[ignore]
fn check_cocktail_dkg_test_vectors_2_of_3() {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use sha2::{Digest, Sha512};
    use std::collections::BTreeMap;

    // Seed from the spec: SHA256("Daniel Bourdrez,Soatok Dreamseeker,Tjaden Hess")
    let seed =
        hex::decode("b171b6992cc6db1f40b18dd8b1361d642f013e4b1208a735259a516af60dcb68").unwrap();
    let cs_id = b"COCKTAIL(Ristretto255, SHA-512)";
    let t: u32 = 2;
    let n: u32 = 3;

    // Derive a 32-byte RNG seed for each participant's Round 1.
    // The spec labels are "round1_participant_{i}".
    let rng_seeds: Vec<[u8; 32]> = (1..=n)
        .map(|i| {
            let label = format!("round1_participant_{}", i);
            let hash = Sha512::new()
                .chain_update(&seed)
                .chain_update(cs_id)
                .chain_update(t.to_le_bytes())
                .chain_update(n.to_le_bytes())
                .chain_update(label.as_bytes())
                .finalize();
            let mut rng_seed = [0u8; 32];
            rng_seed.copy_from_slice(&hash[..32]);
            rng_seed
        })
        .collect();

    // Static secret keys from the spec (little-endian scalar bytes, Ristretto255).
    let static_secret_key_bytes = [
        hex::decode("8232337dffa583f214e2ead7f19c37b482f77171194ed6984a715353e086d20e")
            .unwrap(),
        hex::decode("f7b358f26668f0733363b309c435bc16f7670ec5850e4860c5d25e049e7d060d")
            .unwrap(),
        hex::decode("fc2df6b164cac912a8c2d294b528f5e3261f1724d510f9fd1c2bae5e76308d0b")
            .unwrap(),
    ];

    // Expected outputs from the spec.
    let expected_group_public_key =
        hex::decode("0a1592f555f20d3a3b3c7bc032ebe4b46cb2870da141404873e5fc8d4136120f")
            .unwrap();
    let expected_shares = [
        hex::decode("09b8de601c1d28161f3b18410245595d791de5e54372f19628760125fa263304")
            .unwrap(),
        hex::decode("7db7ccef4df8fb157766082728cd2f072c0ec3af6d352a3d0af49919daf9950b")
            .unwrap(),
        hex::decode("04e3c4216570bdbdf8f4006a6f5b279cdefea07997f862e3eb71320ebaccf802")
            .unwrap(),
    ];

    // Parse static keys and build participants map.
    let identifiers: Vec<Identifier> = (1..=3u16)
        .map(|i| i.try_into().unwrap())
        .collect();

    let mut static_keys: BTreeMap<Identifier, SigningKey> = BTreeMap::new();
    let mut participants: BTreeMap<Identifier, VerifyingKey> = BTreeMap::new();
    for (id, key_bytes) in identifiers.iter().zip(static_secret_key_bytes.iter()) {
        let sk = SigningKey::deserialize(key_bytes).unwrap();
        let vk = VerifyingKey::from(&sk);
        static_keys.insert(*id, sk);
        participants.insert(*id, vk);
    }

    let context = b"COCKTAIL-DKG-TEST-VECTOR-2-OF-3";
    let extension = b"";

    // Round 1: each participant generates their packages using their deterministic RNG.
    let mut round1_secret_packages: BTreeMap<Identifier, keys::cocktail_dkg::round1::SecretPackage> =
        BTreeMap::new();
    let mut received_round1_packages: BTreeMap<
        Identifier,
        BTreeMap<Identifier, keys::cocktail_dkg::round1::Package>,
    > = BTreeMap::new();

    for (idx, (&id, sk)) in static_keys.iter().enumerate() {
        let mut rng = ChaCha20Rng::from_seed(rng_seeds[idx]);
        let (secret_pkg, pkg) = keys::cocktail_dkg::part1(
            id,
            n as u16,
            t as u16,
            sk,
            &participants,
            context,
            &mut rng,
        )
        .unwrap();
        round1_secret_packages.insert(id, secret_pkg);
        for (&receiver_id, _) in &participants {
            if receiver_id != id {
                received_round1_packages
                    .entry(receiver_id)
                    .or_default()
                    .insert(id, pkg.clone());
            }
        }
    }

    // Round 2: each participant decrypts and verifies shares.
    let mut round2_secret_packages: BTreeMap<Identifier, keys::cocktail_dkg::round2::SecretPackage> =
        BTreeMap::new();
    let mut received_round2_packages: BTreeMap<
        Identifier,
        BTreeMap<Identifier, keys::cocktail_dkg::round2::Package>,
    > = BTreeMap::new();

    for (&id, sk) in &static_keys {
        let secret_pkg = round1_secret_packages.remove(&id).unwrap();
        let round1_packages = &received_round1_packages[&id];
        let (r2_secret, r2_pkg) = keys::cocktail_dkg::part2(
            secret_pkg,
            round1_packages,
            sk,
            &participants,
            context,
            extension,
            rand::rngs::OsRng,
        )
        .unwrap();
        round2_secret_packages.insert(id, r2_secret);
        for (&receiver_id, _) in &participants {
            received_round2_packages
                .entry(receiver_id)
                .or_default()
                .insert(id, r2_pkg.clone());
        }
    }

    // Round 3: verify transcript signatures and output final keys.
    for (idx, (&id, _)) in static_keys.iter().enumerate() {
        let r2_secret = &round2_secret_packages[&id];
        let round2_packages = &received_round2_packages[&id];
        let (key_pkg, pubkey_pkg) =
            keys::cocktail_dkg::part3(r2_secret, round2_packages).unwrap();

        // Verify group public key.
        assert_eq!(
            pubkey_pkg.verifying_key().serialize().unwrap().as_slice(),
            expected_group_public_key.as_slice(),
            "participant {} group public key mismatch",
            idx + 1
        );

        // Verify secret share.
        assert_eq!(
            key_pkg.signing_share().serialize().as_slice(),
            expected_shares[idx].as_slice(),
            "participant {} secret share mismatch",
            idx + 1
        );
    }
}
