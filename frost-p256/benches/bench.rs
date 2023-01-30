use criterion::{criterion_group, criterion_main, Criterion};
use rand::thread_rng;

use frost_p256::*;

fn bench_p256_batch_verify(c: &mut Criterion) {
    let mut rng = thread_rng();

    frost_core::benches::bench_batch_verify::<P256Sha256, _>(c, "p256", &mut rng);
}

fn bench_p256_sign(c: &mut Criterion) {
    let mut rng = thread_rng();

    frost_core::benches::bench_sign::<P256Sha256, _>(c, "p256", &mut rng);
}

criterion_group!(benches, bench_p256_batch_verify, bench_p256_sign);
criterion_main!(benches);
