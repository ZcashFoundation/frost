use criterion::{criterion_group, criterion_main, Criterion};

use frost_ed25519::*;
use rand_core::TryRngCore;

fn bench_ed25519_batch_verify(c: &mut Criterion) {
    let mut rng = rand::rngs::OsRng.unwrap_err();

    frost_core::benches::bench_batch_verify::<Ed25519Sha512, _>(c, "ed25519", &mut rng);
}

fn bench_ed25519_sign(c: &mut Criterion) {
    let mut rng = rand::rngs::OsRng.unwrap_err();

    frost_core::benches::bench_sign::<Ed25519Sha512, _>(c, "ed25519", &mut rng);
}

criterion_group!(benches, bench_ed25519_batch_verify, bench_ed25519_sign);
criterion_main!(benches);
