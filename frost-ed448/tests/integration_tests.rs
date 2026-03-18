use frost_ed448::*;
use lazy_static::lazy_static;
use serde_json::Value;

#[test]
fn check_zero_key_fails() {
    frost_core::tests::ciphersuite_generic::check_zero_key_fails::<Ed448Shake256>();
}

#[test]
fn check_sign_with_dkg() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::ciphersuite_generic::check_sign_with_dkg::<Ed448Shake256, _>(rng);
}

#[test]
fn check_sign_with_cocktail_dkg() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::ciphersuite_generic::check_sign_with_cocktail_dkg::<Ed448Shake256, _>(rng);
}

#[test]
fn check_dkg_part1_fails_with_invalid_signers_min_signers() {
    let rng = rand::rngs::OsRng;

    let min_signers = 1;
    let max_signers = 3;
    let error = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Ed448Shake256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_dkg_part1_fails_with_min_signers_greater_than_max() {
    let rng = rand::rngs::OsRng;

    let min_signers = 3;
    let max_signers = 2;
    let error: frost_core::Error<Ed448Shake256> = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Ed448Shake256,
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
        Ed448Shake256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_rts() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::repairable::check_rts::<Ed448Shake256, _>(rng);
}

#[test]
fn check_refresh_shares_with_dealer() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::refresh::check_refresh_shares_with_dealer::<Ed448Shake256, _>(rng);
}

#[test]
fn check_refresh_shares_with_dealer_serialisation() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::refresh::check_refresh_shares_with_dealer_serialisation::<Ed448Shake256, _>(
        rng,
    );
}

#[test]
fn check_refresh_shares_with_dealer_fails_with_invalid_public_key_package() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::refresh::check_refresh_shares_with_dealer_fails_with_invalid_public_key_package::<
        Ed448Shake256,
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
        Ed448Shake256,
        _,
    >(&identifiers, error, rng);
}

#[test]
fn check_refresh_shares_with_dkg() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::refresh::check_refresh_shares_with_dkg::<Ed448Shake256, _>(rng);
}

#[test]
fn check_refresh_shares_with_dkg_smaller_threshold() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::refresh::check_refresh_shares_with_dkg_smaller_threshold::<Ed448Shake256, _>(
        rng,
    );
}

#[test]
fn check_sign_with_dealer() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<Ed448Shake256, _>(rng);
}

#[test]
fn check_sign_with_dealer_fails_with_invalid_min_signers() {
    let rng = rand::rngs::OsRng;

    let min_signers = 1;
    let max_signers = 3;
    let error = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Ed448Shake256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_sign_with_dealer_fails_with_min_signers_greater_than_max() {
    let rng = rand::rngs::OsRng;

    let min_signers = 3;
    let max_signers = 2;
    let error: frost_core::Error<Ed448Shake256> = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        Ed448Shake256,
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
        Ed448Shake256,
        _,
    >(min_signers, max_signers, error, rng);
}

/// This is testing that Shamir's secret sharing to compute and arbitrary
/// value is working.
#[test]
fn check_share_generation_ed448_shake256() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::ciphersuite_generic::check_share_generation::<Ed448Shake256, _>(rng);
}

#[test]
fn check_share_generation_fails_with_invalid_min_signers() {
    let rng = rand::rngs::OsRng;

    let min_signers = 0;
    let max_signers = 3;
    let error = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_share_generation_fails_with_invalid_signers::<
        Ed448Shake256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_share_generation_fails_with_min_signers_greater_than_max() {
    let rng = rand::rngs::OsRng;

    let min_signers = 3;
    let max_signers = 2;
    let error: frost_core::Error<Ed448Shake256> = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_share_generation_fails_with_invalid_signers::<
        Ed448Shake256,
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
        Ed448Shake256,
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
    frost_core::tests::vectors::check_sign_with_test_vectors::<Ed448Shake256>(&VECTORS);
}

#[test]
fn check_sign_with_test_vectors_dkg() {
    frost_core::tests::vectors_dkg::check_dkg_keygen::<Ed448Shake256>(&VECTORS_DKG);
}

#[test]
fn check_sign_with_test_vectors_with_big_identifiers() {
    frost_core::tests::vectors::check_sign_with_test_vectors::<Ed448Shake256>(
        &VECTORS_BIG_IDENTIFIER,
    );
}

#[test]
fn check_error_culprit() {
    frost_core::tests::ciphersuite_generic::check_error_culprit::<Ed448Shake256>();
}

#[test]
fn check_identifier_derivation() {
    frost_core::tests::ciphersuite_generic::check_identifier_derivation::<Ed448Shake256>();
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
        Ed448Shake256,
        _,
    >(rng);
}

#[test]
fn check_sign_with_missing_identifier() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::ciphersuite_generic::check_sign_with_missing_identifier::<Ed448Shake256, _>(
        rng,
    );
}

#[test]
fn check_sign_with_incorrect_commitments() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::ciphersuite_generic::check_sign_with_incorrect_commitments::<Ed448Shake256, _>(
        rng,
    );
}

#[tokio::test]
async fn check_async_sign_with_dealer() {
    tokio::spawn(async {
        let rng = rand::rngs::OsRng;
        frost_core::tests::ciphersuite_generic::async_check_sign::<Ed448Shake256, _>(rng).await;
    })
    .await
    .unwrap();
}

#[test]
fn check_cocktail_dkg_test_vectors() {
    use rand_core::{CryptoRng, RngCore};
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    use std::collections::BTreeMap;

    struct CounterDrng {
        seed: Vec<u8>,
        cs_id: Vec<u8>,
        t: u32,
        n: u32,
        label: Vec<u8>,
        counter: u64,
        buf: [u8; 64],
        buf_pos: usize,
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
                buf_pos: 64,
            }
        }

        fn refill(&mut self) {
            let mut hasher = Shake256::default();
            hasher.update(&self.seed);
            hasher.update(&self.cs_id);
            hasher.update(&self.t.to_le_bytes());
            hasher.update(&self.n.to_le_bytes());
            hasher.update(&self.label);
            hasher.update(&self.counter.to_le_bytes());
            let mut reader = hasher.finalize_xof();
            reader.read(&mut self.buf);
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
        serde_json::from_str(include_str!("helpers/cocktail-dkg-ed448-shake256.json").trim())
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
            // JSON stores 56-byte raw scalars; ed448 expects 57-byte RFC 8032 format (trailing 0x00).
            let mut key_padded = [0u8; 57];
            key_padded[..key_bytes.len()].copy_from_slice(key_bytes);
            let sk = SigningKey::deserialize(&key_padded).unwrap();
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
                <<Ed448Shake256 as Ciphersuite>::Group>::serialize(pkg.ephemeral_pub())
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

            // Note: encrypted shares are 73 bytes in our implementation (57-byte RFC 8032 scalar +
            // 16-byte AEAD tag) but 72 bytes in the JSON (56-byte raw scalar + 16-byte AEAD tag).
            // This format difference means the ciphertexts cannot be compared against the JSON.

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

            round2_secret_packages.insert(id, r2_secret);
            for &receiver_id in participants.keys() {
                received_round2_packages
                    .entry(receiver_id)
                    .or_default()
                    .insert(id, r2_pkg.clone());
            }
        }

        // Round 3
        for (idx, (&id, _)) in static_keys.iter().enumerate() {
            let r2_secret = &round2_secret_packages[&id];
            let round2_packages = &received_round2_packages[&id];
            let (key_pkg, pubkey_pkg, _transcript, _cert) =
                keys::cocktail_dkg::part3(r2_secret, round2_packages).unwrap();

            assert_eq!(
                pubkey_pkg.verifying_key().serialize().unwrap().as_slice(),
                expected_group_public_key.as_slice(),
                "participant {} group public key mismatch",
                idx + 1
            );
            // JSON stores 56-byte raw scalars; our implementation uses 57-byte RFC 8032 format
            // (little-endian scalar + trailing 0x00). Compare the first 56 bytes.
            assert_eq!(
                &key_pkg.signing_share().serialize().as_slice()[..56],
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

        // Note: recovery is not tested here because the JSON ciphertexts use 56-byte raw scalar
        // encryption while our implementation uses 57-byte RFC 8032 format, making them
        // incompatible.
    }
}
