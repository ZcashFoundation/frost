//! COCKTAIL-DKG test functions.
#![allow(clippy::type_complexity)]
#![cfg(feature = "serialization")]

use alloc::{collections::BTreeMap, vec::Vec};
use rand_core::{CryptoRng, RngCore};

use crate as frost;
use crate::keys::cocktail_dkg::CocktailCiphersuite;
use crate::keys::{KeyPackage, SigningShare, VerifyingShare};
use crate::{
    keys::PublicKeyPackage, Ciphersuite, Group, Identifier, Signature, SigningKey, VerifyingKey,
};

use super::ciphersuite_generic::check_sign;

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
/// - `hash_fn`: The ciphersuite's hash function `H`, also used as a
///   counter-based RNG for test vectors. E.g. `|data| Sha256::digest(data).to_vec()`.
pub fn check_cocktail_dkg_test_vectors<C, H>(json: &str, hash_fn: H)
where
    C: CocktailCiphersuite,
    H: Fn(&[u8]) -> Vec<u8>,
{
    let file: serde_json::Value = serde_json::from_str(json.trim()).unwrap();
    let seed = hex::decode(file["seed"].as_str().unwrap()).unwrap();
    let cs_id = file["ciphersuite"].as_str().unwrap().as_bytes().to_vec();
    assert_eq!(
        cs_id,
        C::COCKTAIL_ID.as_bytes(),
        "test vector ciphersuite mismatch"
    );
    let hash_fn_ref: &dyn Fn(&[u8]) -> Vec<u8> = &hash_fn;

    for vector in file["vectors"].as_array().unwrap().iter() {
        let n = vector["n"].as_u64().unwrap() as u32;
        let t = vector["t"].as_u64().unwrap() as u32;
        let context = hex::decode(vector["context"].as_str().unwrap()).unwrap();
        let session_tag = hex::decode(vector["session_tag"].as_str().unwrap()).unwrap();
        let extension = hex::decode(vector["extension"].as_str().unwrap()).unwrap();

        let static_secret_key_bytes: Vec<Vec<u8>> = vector["config"]["static_secret_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
            .collect();

        let static_public_key_bytes: Vec<Vec<u8>> = vector["config"]["static_public_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
            .collect();

        // Per-participant broadcast payloads (present in the payload-extension
        // vector variant only).
        let payloads: Vec<Vec<u8>> = vector
            .get("payloads")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
                    .collect()
            })
            .unwrap_or_default();

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

        let identifiers: Vec<Identifier<C>> =
            (1..=n as u16).map(|i| i.try_into().unwrap()).collect();

        let mut static_keys: BTreeMap<Identifier<C>, SigningKey<C>> = BTreeMap::new();
        let mut participants: BTreeMap<Identifier<C>, VerifyingKey<C>> = BTreeMap::new();
        for (idx, (id, key_bytes)) in identifiers
            .iter()
            .zip(static_secret_key_bytes.iter())
            .enumerate()
        {
            // Try direct deserialization first; if it fails (wrong length), append one zero
            // byte and retry. This handles ed448 where JSON stores 56-byte raw scalars but
            // the ciphersuite uses 57-byte RFC 8032 format (trailing 0x00).
            let sk = SigningKey::<C>::deserialize(key_bytes).unwrap_or_else(|_| {
                let mut padded = key_bytes.clone();
                padded.push(0);
                SigningKey::<C>::deserialize(&padded).unwrap()
            });
            let vk = VerifyingKey::from(&sk);
            assert_eq!(
                vk.serialize().unwrap(),
                static_public_key_bytes[idx],
                "participant {} static public key mismatch",
                idx + 1
            );
            static_keys.insert(*id, sk);
            participants.insert(*id, vk);
        }

        // Check that the vector's context follows the recommended construction:
        // H("COCKTAIL-DKG-CONTEXT" || uint64_be(len(session_tag)) || session_tag
        //   || uint64_be(len(ciphersuite_id)) || ciphersuite_id || uint32_le(n)
        //   || P_1 || ... || P_n)
        let mut context_preimage = b"COCKTAIL-DKG-CONTEXT".to_vec();
        context_preimage.extend_from_slice(&(session_tag.len() as u64).to_be_bytes());
        context_preimage.extend_from_slice(&session_tag);
        context_preimage.extend_from_slice(&(cs_id.len() as u64).to_be_bytes());
        context_preimage.extend_from_slice(&cs_id);
        context_preimage.extend_from_slice(&n.to_le_bytes());
        for pk in participants.values() {
            context_preimage.extend_from_slice(&pk.serialize().unwrap());
        }
        assert_eq!(hash_fn(&context_preimage), context, "context mismatch");

        // Check that the vector's extension follows the recommended payload
        // commitment construction when payloads are present:
        // H(uint64_le(n) || uint64_le(len(payload_1)) || payload_1 || ...)
        if !payloads.is_empty() {
            let mut ext_preimage = (n as u64).to_le_bytes().to_vec();
            for payload in &payloads {
                ext_preimage.extend_from_slice(&(payload.len() as u64).to_le_bytes());
                ext_preimage.extend_from_slice(payload);
            }
            assert_eq!(hash_fn(&ext_preimage), extension, "extension mismatch");
        }

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
            // Each participant broadcasts the same payload to every recipient.
            let sender_payloads: BTreeMap<Identifier<C>, Vec<u8>> = if payloads.is_empty() {
                BTreeMap::new()
            } else {
                identifiers
                    .iter()
                    .map(|&receiver_id| (receiver_id, payloads[idx].clone()))
                    .collect()
            };
            let (secret_pkg, pkg) = frost::keys::cocktail_dkg::part1(
                id,
                n as u16,
                t as u16,
                sk,
                &participants,
                &context,
                &sender_payloads,
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

            let expected_pop = hex::decode(round1_tv["pop"].as_str().unwrap()).unwrap();
            assert_eq!(
                frost::keys::cocktail_dkg::serialize_signature(pkg.proof_of_possession()).unwrap(),
                expected_pop,
                "participant {} PoP mismatch",
                idx + 1
            );

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
            let (r2_secret, r2_pkg, received_payloads) = frost::keys::cocktail_dkg::part2(
                secret_pkg,
                round1_packages,
                sk,
                &participants,
                &context,
                &extension,
            )
            .unwrap();

            // Each decrypted payload must round-trip to the sender's payload.
            for (sender_id, payload) in &received_payloads {
                let sender_idx = identifiers.iter().position(|i| i == sender_id).unwrap();
                let expected: &[u8] = payloads
                    .get(sender_idx)
                    .map(|p| p.as_slice())
                    .unwrap_or(&[]);
                assert_eq!(payload.as_slice(), expected, "payload mismatch");
            }

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

        // Build expected packages from test vector data and apply post_dkg.
        // Some ciphersuites (e.g. secp256k1-tr) apply transformations in post_dkg
        // (like a taproot tweak) that are not reflected in the test vectors.
        let expected_vk = VerifyingKey::<C>::deserialize(&expected_group_public_key).unwrap();
        let expected_vshares_map: BTreeMap<Identifier<C>, VerifyingShare<C>> = identifiers
            .iter()
            .zip(expected_verification_shares.iter())
            .map(|(id, bytes)| (*id, VerifyingShare::<C>::deserialize(bytes).unwrap()))
            .collect();
        let expected_signing_shares_parsed: Vec<SigningShare<C>> = expected_shares
            .iter()
            .map(|bytes| {
                SigningShare::<C>::deserialize(bytes).unwrap_or_else(|_| {
                    let mut padded = bytes.clone();
                    padded.push(0);
                    SigningShare::<C>::deserialize(&padded).unwrap()
                })
            })
            .collect();
        // Compute the tweaked pubkey package (same for all participants).
        let expected_tweaked_pubkey_pkg = {
            let pkp_raw = PublicKeyPackage::<C>::new(
                expected_vshares_map.clone(),
                expected_vk,
                Some(t as u16),
            );
            let id0 = identifiers[0];
            let kp0 = KeyPackage::<C>::new(
                id0,
                expected_signing_shares_parsed[0],
                *expected_vshares_map.get(&id0).unwrap(),
                expected_vk,
                t as u16,
            );
            let (_, tweaked_pkp) = C::post_dkg(kp0, pkp_raw).unwrap();
            tweaked_pkp
        };
        // Compute per-participant tweaked key packages.
        let expected_tweaked_key_pkgs: Vec<KeyPackage<C>> = identifiers
            .iter()
            .zip(expected_signing_shares_parsed.iter())
            .map(|(id, ss)| {
                let pkp = PublicKeyPackage::<C>::new(
                    expected_vshares_map.clone(),
                    expected_vk,
                    Some(t as u16),
                );
                let kp = KeyPackage::<C>::new(
                    *id,
                    *ss,
                    *expected_vshares_map.get(id).unwrap(),
                    expected_vk,
                    t as u16,
                );
                let (tweaked_kp, _) = C::post_dkg(kp, pkp).unwrap();
                tweaked_kp
            })
            .collect();

        for (idx, (&id, _)) in static_keys.iter().enumerate() {
            let r2_secret = &round2_secret_packages[&id];
            let round2_packages = &received_round2_packages[&id];
            let (key_pkg, pubkey_pkg, transcript, cert) =
                frost::keys::cocktail_dkg::part3(r2_secret, round2_packages).unwrap();

            if idx == 0 {
                // The canonical transcript and the success certificate are
                // identical for all participants; compare them against the
                // vector once.
                assert_eq!(
                    hash_fn(&transcript),
                    hex::decode(vector["round3"]["transcript_hash"].as_str().unwrap()).unwrap(),
                    "transcript hash mismatch"
                );
                for sig_tv in vector["round3"]["signatures"].as_array().unwrap() {
                    let signer_id =
                        Identifier::<C>::try_from(sig_tv["signer_id"].as_u64().unwrap() as u16)
                            .unwrap();
                    let expected_sig = hex::decode(sig_tv["signature"].as_str().unwrap()).unwrap();
                    assert_eq!(
                        frost::keys::cocktail_dkg::serialize_signature(&cert[&signer_id]).unwrap(),
                        expected_sig,
                        "round 3 signature mismatch for signer {:?}",
                        sig_tv["signer_id"]
                    );
                }

                transcript_for_recovery = transcript;
                cert_for_recovery = cert;
            }

            assert_eq!(
                pubkey_pkg.verifying_key().serialize().unwrap().as_slice(),
                expected_tweaked_pubkey_pkg
                    .verifying_key()
                    .serialize()
                    .unwrap()
                    .as_slice(),
                "participant {} group public key mismatch",
                idx + 1
            );

            assert_eq!(
                key_pkg.signing_share().serialize(),
                expected_tweaked_key_pkgs[idx].signing_share().serialize(),
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
                expected_tweaked_pubkey_pkg
                    .verifying_shares()
                    .get(&id)
                    .unwrap()
                    .serialize()
                    .unwrap()
                    .as_slice(),
                "participant {} verification share mismatch",
                idx + 1
            );
        }

        // Recovery
        {
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
                let expected_recovered_vshare =
                    hex::decode(recovery["recovered_verification_share"].as_str().unwrap())
                        .unwrap();

                // Apply post_dkg to the expected recovered key package.
                let expected_tweaked_recovery_kp = {
                    let recovered_ss = SigningShare::<C>::deserialize(&expected_recovered_share)
                        .unwrap_or_else(|_| {
                            // ed448: 56-byte JSON scalar vs 57-byte RFC 8032 format.
                            let mut padded = expected_recovered_share.clone();
                            padded.push(0);
                            SigningShare::<C>::deserialize(&padded).unwrap()
                        });
                    let recovered_vs =
                        VerifyingShare::<C>::deserialize(&expected_recovered_vshare).unwrap();
                    let kp = KeyPackage::<C>::new(
                        recovery_identifier,
                        recovered_ss,
                        recovered_vs,
                        expected_vk,
                        t as u16,
                    );
                    let pkp = PublicKeyPackage::<C>::new(
                        expected_vshares_map.clone(),
                        expected_vk,
                        Some(t as u16),
                    );
                    let (tweaked_kp, _) = C::post_dkg(kp, pkp).unwrap();
                    tweaked_kp
                };

                let (recovered_key_pkg, recovered_pubkey_pkg) = frost::keys::cocktail_dkg::recover(
                    recovery_sk,
                    &transcript_for_recovery,
                    &cert_for_recovery,
                    &recovery_ciphertexts,
                )
                .unwrap();

                assert_eq!(
                    recovered_key_pkg.signing_share().serialize().as_slice(),
                    expected_tweaked_recovery_kp
                        .signing_share()
                        .serialize()
                        .as_slice(),
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
                    expected_tweaked_pubkey_pkg
                        .verifying_shares()
                        .get(&recovery_identifier)
                        .unwrap()
                        .serialize()
                        .unwrap()
                        .as_slice(),
                    "recovered verification share mismatch"
                );
            }
        }
    }
}
