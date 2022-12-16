//! Ciphersuite-generic benchmark functions.

use std::collections::HashMap;

use criterion::{BenchmarkId, Criterion, Throughput};
use rand_core::{CryptoRng, RngCore};

use crate::{batch, frost, Ciphersuite, Signature, SigningKey, VerifyingKey};

struct Item<C: Ciphersuite> {
    vk: VerifyingKey<C>,
    sig: Signature<C>,
}

fn sigs_with_distinct_keys<C: Ciphersuite, R: RngCore + CryptoRng + Clone>(
    rng: &mut R,
) -> impl Iterator<Item = Item<C>> {
    let mut rng = rng.clone();
    std::iter::repeat_with(move || {
        let msg = b"Bench";
        let sk = SigningKey::new(&mut rng);
        let vk = VerifyingKey::from(&sk);
        let sig = sk.sign(&mut rng, &msg[..]);
        Item { vk, sig }
    })
}

/// Benchmark batched signature verification with the specified ciphersuite.
pub fn bench_batch_verify<C: Ciphersuite, R: RngCore + CryptoRng + Clone>(
    c: &mut Criterion,
    name: &str,
    rng: &mut R,
) {
    let mut group = c.benchmark_group(format!("Batch Verification {}", name));
    for &n in [8usize, 16, 24, 32, 40, 48, 56, 64].iter() {
        group.throughput(Throughput::Elements(n as u64));

        let sigs = sigs_with_distinct_keys::<C, R>(rng)
            .take(n)
            .collect::<Vec<_>>();

        group.bench_with_input(
            BenchmarkId::new("Unbatched verification", n),
            &sigs,
            |b, sigs| {
                b.iter(|| {
                    for item in sigs.iter() {
                        let msg = b"Bench";

                        let Item { vk, sig } = item;
                        {
                            let _ = vk.verify(msg, sig);
                        }
                    }
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("Batched verification", n),
            &sigs,
            |b, sigs| {
                let mut rng = rng.clone();
                b.iter(|| {
                    let mut batch = batch::Verifier::new();
                    for item in sigs.iter() {
                        let msg = b"Bench";

                        let Item { vk, sig } = item;
                        {
                            batch.queue((*vk, *sig, msg));
                        }
                    }
                    batch.verify(&mut rng)
                })
            },
        );
    }
    group.finish();
}

/// Benchmark FROST signing with the specified ciphersuite.
pub fn bench_sign<C: Ciphersuite, R: RngCore + CryptoRng + Clone>(
    c: &mut Criterion,
    name: &str,
    rng: &mut R,
) {
    let mut group = c.benchmark_group(format!("FROST Signing {}", name));
    for &n in [3u16, 10, 100, 1000].iter() {
        let max_signers = n;
        let min_signers = (n * 2 + 2) / 3;

        group.bench_with_input(
            BenchmarkId::new("Key Generation with Dealer", max_signers),
            &(max_signers, min_signers),
            |b, (max_signers, min_signers)| {
                let mut rng = rng.clone();
                b.iter(|| {
                    let (_shares, _pubkeys) = frost::keys::keygen_with_dealer::<C, R>(
                        *max_signers,
                        *min_signers,
                        &mut rng,
                    )
                    .unwrap();
                })
            },
        );

        let (shares, pubkeys) =
            frost::keys::keygen_with_dealer::<C, R>(max_signers, min_signers, rng).unwrap();

        // Verifies the secret shares from the dealer
        let key_packages: HashMap<_, _> = shares
            .into_iter()
            .map(|share| {
                (
                    share.identifier,
                    frost::keys::KeyPackage::try_from(share).unwrap(),
                )
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("Round 1", min_signers),
            &key_packages,
            |b, key_packages| {
                b.iter(|| {
                    let participant_identifier = 1u16.try_into().expect("should be nonzero");
                    let (_nonce, _commitment) = frost::round1::commit(
                        participant_identifier,
                        key_packages
                            .get(&participant_identifier)
                            .unwrap()
                            .secret_share(),
                        rng,
                    );
                })
            },
        );

        let mut nonces: HashMap<_, _> = HashMap::new();
        let mut commitments: HashMap<_, _> = HashMap::new();

        for participant_index in 1..(min_signers + 1) {
            let participant_identifier = participant_index.try_into().expect("should be nonzero");
            let (nonce, commitment) = frost::round1::commit(
                participant_identifier,
                key_packages
                    .get(&participant_identifier)
                    .unwrap()
                    .secret_share(),
                rng,
            );
            nonces.insert(participant_identifier, nonce);
            commitments.insert(participant_identifier, commitment);
        }

        let message = "message to sign".as_bytes();
        let comms = commitments.clone().into_values().collect();
        let signing_package = frost::SigningPackage::new(comms, message.to_vec());

        group.bench_with_input(
            BenchmarkId::new("Round 2", min_signers),
            &(
                key_packages.clone(),
                nonces.clone(),
                signing_package.clone(),
            ),
            |b, (key_packages, nonces, signing_package)| {
                b.iter(|| {
                    let participant_identifier = 1u16.try_into().expect("should be nonzero");
                    let key_package = key_packages.get(&participant_identifier).unwrap();
                    let nonces_to_use = &nonces.get(&participant_identifier).unwrap();
                    let _signature_share =
                        frost::round2::sign(signing_package, nonces_to_use, key_package).unwrap();
                })
            },
        );

        let mut signature_shares = Vec::new();
        for participant_identifier in nonces.keys() {
            let key_package = key_packages.get(participant_identifier).unwrap();
            let nonces_to_use = &nonces.get(participant_identifier).unwrap();
            let signature_share =
                frost::round2::sign(&signing_package, nonces_to_use, key_package).unwrap();
            signature_shares.push(signature_share);
        }

        group.bench_with_input(
            BenchmarkId::new("Aggregate", min_signers),
            &(signing_package.clone(), signature_shares.clone(), pubkeys),
            |b, (signing_package, signature_shares, pubkeys)| {
                b.iter(|| {
                    let _group_signature_ =
                        frost::aggregate(signing_package, &signature_shares[..], pubkeys).unwrap();
                })
            },
        );
    }
    group.finish();
}
