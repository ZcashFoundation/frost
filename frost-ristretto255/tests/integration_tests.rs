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

/// Test COCKTAIL-DKG with the 2-of-3 test vectors from the CCTV JSON file.
///
/// The derivation scheme (from the CCTV JSON) is counter-based SHA-512:
///   scalar(participant_i, counter_j) = wide_reduce(
///       SHA-512(seed || cs_id || uint32_le(t) || uint32_le(n)
///               || "round1_participant_i" || uint64_le(j))
///   )
/// Scalars are generated in order: a_0 (j=0), a_1 (j=1), …, a_{t-1} (j=t-1), e_i (j=t).
#[test]
fn check_cocktail_dkg_test_vectors() {
    use rand_core::{CryptoRng, RngCore};
    use sha2::{Digest, Sha512};
    use std::collections::BTreeMap;

    /// Counter-based deterministic RNG for COCKTAIL-DKG test vectors.
    ///
    /// Each 64-byte block is:
    ///   SHA-512(seed || cs_id || uint32_le(t) || uint32_le(n) || label || uint64_le(counter))
    struct CounterDrng {
        seed: Vec<u8>,
        cs_id: Vec<u8>,
        t: u32,
        n: u32,
        label: Vec<u8>,
        counter: u64,
        buf: [u8; 64],
        buf_pos: usize, // 64 means buffer is empty and needs refill
    }

    impl CounterDrng {
        fn new(seed: &[u8], cs_id: &[u8], t: u32, n: u32, participant: u32) -> Self {
            Self {
                seed: seed.to_vec(),
                cs_id: cs_id.to_vec(),
                t,
                n,
                label: format!("round1_participant_{}", participant).into_bytes(),
                counter: 0,
                buf: [0u8; 64],
                buf_pos: 64, // empty; first fill_bytes triggers refill
            }
        }

        fn refill(&mut self) {
            let hash: [u8; 64] = Sha512::new()
                .chain_update(&self.seed)
                .chain_update(&self.cs_id)
                .chain_update(self.t.to_le_bytes())
                .chain_update(self.n.to_le_bytes())
                .chain_update(&self.label)
                .chain_update(self.counter.to_le_bytes())
                .finalize()
                .into();
            self.buf = hash;
            self.buf_pos = 0;
            self.counter += 1;
        }
    }

    impl RngCore for CounterDrng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let mut pos = 0;
            while pos < dest.len() {
                if self.buf_pos == 64 {
                    self.refill();
                }
                let available = 64 - self.buf_pos;
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

    impl CryptoRng for CounterDrng {}

    let file: serde_json::Value =
        serde_json::from_str(include_str!("helpers/cocktail-dkg-ristretto255-sha512.json").trim())
            .unwrap();

    let seed = hex::decode(file["seed"].as_str().unwrap()).unwrap();
    let cs_id = file["ciphersuite"].as_str().unwrap().as_bytes().to_vec();

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

        let identifiers: Vec<Identifier> = (1..=n as u16).map(|i| i.try_into().unwrap()).collect();

        let mut static_keys: BTreeMap<Identifier, SigningKey> = BTreeMap::new();
        let mut participants: BTreeMap<Identifier, VerifyingKey> = BTreeMap::new();
        for (id, key_bytes) in identifiers.iter().zip(static_secret_key_bytes.iter()) {
            let sk = SigningKey::deserialize(key_bytes).unwrap();
            let vk = VerifyingKey::from(&sk);
            static_keys.insert(*id, sk);
            participants.insert(*id, vk);
        }

        let extension = b"";

        // Round 1
        let mut round1_secret_packages: BTreeMap<
            Identifier,
            keys::cocktail_dkg::round1::SecretPackage,
        > = BTreeMap::new();
        let mut received_round1_packages: BTreeMap<
            Identifier,
            BTreeMap<Identifier, keys::cocktail_dkg::round1::Package>,
        > = BTreeMap::new();

        for (idx, (&id, sk)) in static_keys.iter().enumerate() {
            let mut rng = CounterDrng::new(&seed, &cs_id, t, n, (idx + 1) as u32);
            let (secret_pkg, pkg) = keys::cocktail_dkg::part1(
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
                <<Ristretto255Sha512 as Ciphersuite>::Group>::serialize(pkg.ephemeral_pub())
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

            // Note: the JSON PoP values were generated with an unknown signing scheme
            // incompatible with the COCKTAIL spec's deterministic Schnorr. We verify
            // self-consistency (our PoP verifies under our pop_verify) in unit tests.

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
            Identifier,
            keys::cocktail_dkg::round2::SecretPackage,
        > = BTreeMap::new();
        let mut received_round2_packages: BTreeMap<
            Identifier,
            BTreeMap<Identifier, keys::cocktail_dkg::round2::Package>,
        > = BTreeMap::new();

        for (&id, sk) in static_keys.iter() {
            let secret_pkg = round1_secret_packages.remove(&id).unwrap();
            let round1_packages = &received_round1_packages[&id];
            let (r2_secret, r2_pkg, _received_payloads) = keys::cocktail_dkg::part2(
                secret_pkg,
                round1_packages,
                sk,
                &participants,
                &context,
                extension,
                rand::rngs::OsRng,
            )
            .unwrap();

            // Note: transcript signatures depend on the PoP bytes (which differ from JSON),
            // so they cannot be checked against the JSON test vectors here.

            round2_secret_packages.insert(id, r2_secret);
            for &receiver_id in participants.keys() {
                received_round2_packages
                    .entry(receiver_id)
                    .or_default()
                    .insert(id, r2_pkg.clone());
            }
        }

        // Round 3 — save the transcript and certificate from participant 1 for recovery.
        let mut transcript_for_recovery: Vec<u8> = Vec::new();
        let mut cert_for_recovery: BTreeMap<Identifier, Signature> = BTreeMap::new();

        for (idx, (&id, _)) in static_keys.iter().enumerate() {
            let r2_secret = &round2_secret_packages[&id];
            let round2_packages = &received_round2_packages[&id];
            let (key_pkg, pubkey_pkg, transcript, cert) =
                keys::cocktail_dkg::part3(r2_secret, round2_packages).unwrap();

            // All participants must produce the same transcript.
            if idx == 0 {
                transcript_for_recovery = transcript;
                cert_for_recovery = cert;
            }

            assert_eq!(
                pubkey_pkg.verifying_key().serialize().unwrap().as_slice(),
                expected_group_public_key.as_slice(),
                "participant {} group public key mismatch",
                idx + 1
            );
            assert_eq!(
                key_pkg.signing_share().serialize().as_slice(),
                expected_shares[idx].as_slice(),
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

        // Recovery: only for vectors that include recovery test data.
        if let Some(recovery) = vector.get("recovery") {
            let recovery_id = recovery["participant_id"].as_u64().unwrap() as u16;
            let recovery_identifier = Identifier::try_from(recovery_id).unwrap();
            let recovery_sk = static_keys.get(&recovery_identifier).unwrap();

            // Build ciphertexts map: sender_id -> c_{sender, recovery_participant}
            let ciphertexts_json = recovery["ciphertexts"].as_array().unwrap();
            let mut recovery_ciphertexts: BTreeMap<Identifier, Vec<u8>> = BTreeMap::new();
            for (j_idx, ct) in ciphertexts_json.iter().enumerate() {
                let sender_id = Identifier::try_from((j_idx + 1) as u16).unwrap();
                recovery_ciphertexts.insert(sender_id, hex::decode(ct.as_str().unwrap()).unwrap());
            }

            let expected_recovered_share =
                hex::decode(recovery["recovered_secret_share"].as_str().unwrap()).unwrap();
            let expected_recovered_vshare =
                hex::decode(recovery["recovered_verification_share"].as_str().unwrap()).unwrap();

            let (recovered_key_pkg, recovered_pubkey_pkg) = keys::cocktail_dkg::recover(
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
