use criterion::{criterion_group, criterion_main, Criterion};
use rand::thread_rng;

use frost_p384::*;

fn bench_p256_batch_verify(c: &mut Criterion) {
    let mut rng = thread_rng();

    frost_core::benches::bench_batch_verify::<P384Sha384, _>(c, "p256", &mut rng);
}

fn bench_p256_sign(c: &mut Criterion) {
    let mut rng = thread_rng();

    frost_core::benches::bench_sign::<P384Sha384, _>(c, "p256", &mut rng);
}

criterion_group!(benches, bench_p256_batch_verify, bench_p256_sign);
criterion_main!(benches);
