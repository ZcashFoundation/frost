use criterion::{criterion_group, criterion_main, Criterion};
use rand::thread_rng;

use frost_ecgfp5::*;

fn bench_ecgfp5_batch_verify(c: &mut Criterion) {
    let mut rng = thread_rng();

    frost_core::benches::bench_batch_verify::<EcGFp5Poseidon256, _>(c, "ecGFp5", &mut rng);
}

fn bench_ecgfp5_sign(c: &mut Criterion) {
    let mut rng = thread_rng();

    frost_core::benches::bench_sign::<EcGFp5Poseidon256, _>(c, "ecGFp5", &mut rng);
}

criterion_group!(benches, bench_ecgfp5_batch_verify, bench_ecgfp5_sign);
criterion_main!(benches);
