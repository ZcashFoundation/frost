use criterion::{criterion_group, criterion_main, Criterion};
use rand::thread_rng;

use frost_secp256k1::*;

fn bench_secp256k1_batch_verify(c: &mut Criterion) {
    let mut rng = thread_rng();

    frost_core::benches::bench_batch_verify::<Secp256K1Sha256, _>(c, "secp256k1", &mut rng);
}

fn bench_secp256k1_sign(c: &mut Criterion) {
    let mut rng = thread_rng();

    frost_core::benches::bench_sign::<Secp256K1Sha256, _>(c, "secp256k1", &mut rng);
}

criterion_group!(benches, bench_secp256k1_batch_verify, bench_secp256k1_sign);
criterion_main!(benches);
