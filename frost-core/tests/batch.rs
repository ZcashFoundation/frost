use rand::thread_rng;

use frost_core::*;

mod common;

use common::ciphersuite::Ristretto255Sha512 as R;

#[test]
fn batch_verify() {
    let mut rng = thread_rng();
    let mut batch = batch::Verifier::<R>::new();
    for _ in 0..32 {
        let sk = SigningKey::new(&mut rng);
        let vk = VerifyingKey::<R>::from(&sk);
        let msg = b"BatchVerifyTest";
        let sig = sk.sign(&mut rng, &msg[..]);
        batch.queue((vk.into(), sig, msg));
    }
    assert!(batch.verify(rng).is_ok());
}

#[test]
fn bad_batch_verify() {
    let mut rng = thread_rng();
    let bad_index = 4; // must be even
    let mut batch = batch::Verifier::<R>::new();
    let mut items = Vec::new();
    for i in 0..32 {
        let item: batch::Item<R> = match i % 2 {
            0 => {
                let sk = SigningKey::new(&mut rng);
                let vk = VerifyingKey::<R>::from(&sk);
                let msg = b"BatchVerifyTest";
                let sig = if i != bad_index {
                    sk.sign(&mut rng, &msg[..])
                } else {
                    sk.sign(&mut rng, b"bad")
                };
                (vk.into(), sig, msg).into()
            }
            1 => {
                let sk = SigningKey::new(&mut rng);
                let vk = VerifyingKey::<R>::from(&sk);
                let msg = b"BatchVerifyTest";
                let sig = sk.sign(&mut rng, &msg[..]);
                (vk.into(), sig, msg).into()
            }
            _ => unreachable!(),
        };
        items.push(item.clone());
        batch.queue(item);
    }
    assert!(batch.verify(rng).is_err());
    for (i, item) in items.drain(..).enumerate() {
        if i != bad_index {
            assert!(item.verify_single().is_ok());
        } else {
            assert!(item.verify_single().is_err());
        }
    }
}
