use criterion::{criterion_group, criterion_main, Criterion};
use rand::thread_rng;

use frost_ristretto255::*;

fn bench_ristretto255_batch_verify(c: &mut Criterion) {
    let mut rng = thread_rng();

    frost_core::benches::bench_batch_verify::<Ristretto255Sha512, _>(c, "ristretto255", &mut rng);
}

fn bench_ristretto255_sign(c: &mut Criterion) {
    let mut rng = thread_rng();

    frost_core::benches::bench_sign::<Ristretto255Sha512, _>(c, "ristretto255", &mut rng);
}

criterion_group!(
    benches,
    bench_ristretto255_batch_verify,
    bench_ristretto255_sign
);
criterion_main!(benches);
