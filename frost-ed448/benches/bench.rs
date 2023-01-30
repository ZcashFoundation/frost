use criterion::{criterion_group, criterion_main, Criterion};
use rand::thread_rng;

use frost_ed448::*;

// bench_ed448_batch_verify not included until batch verification is fixed for Ed448
#[allow(unused)]
fn bench_ed448_batch_verify(c: &mut Criterion) {
    let mut rng = thread_rng();

    frost_core::benches::bench_batch_verify::<Ed448Shake256, _>(c, "ed448", &mut rng);
}

fn bench_ed448_sign(c: &mut Criterion) {
    let mut rng = thread_rng();

    frost_core::benches::bench_sign::<Ed448Shake256, _>(c, "ed448", &mut rng);
}

criterion_group!(benches, bench_ed448_sign);
criterion_main!(benches);
