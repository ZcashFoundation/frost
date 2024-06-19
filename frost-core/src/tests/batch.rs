//! Ciphersuite-generic batch test functions.
use crate::*;

/// Test batch verification with a Ciphersuite.
pub fn batch_verify<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    let mut batch = batch::Verifier::<C>::new();
    for _ in 0..1 {
        let sk = SigningKey::new(&mut rng);
        let vk = VerifyingKey::<C>::from(&sk);
        let msg = b"BatchVerifyTest";
        let sig = sk.sign(&mut rng, &msg[..]);
        assert!(vk.verify(msg, &sig).is_ok());
        batch.queue(batch::Item::<C>::new(vk, sig, msg).unwrap());
    }
    assert!(batch.verify(rng).is_ok());
}

/// Test failure case of batch verification with a Ciphersuite.
pub fn bad_batch_verify<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    let bad_index = 4; // must be even
    let mut batch = batch::Verifier::<C>::new();
    let mut items = Vec::new();
    for i in 0..32 {
        let item: batch::Item<C> = match i % 2 {
            0 => {
                let sk = SigningKey::new(&mut rng);
                let vk = VerifyingKey::<C>::from(&sk);
                let msg = b"BatchVerifyTest";
                let sig = if i != bad_index {
                    sk.sign(&mut rng, &msg[..])
                } else {
                    sk.sign(&mut rng, b"bad")
                };
                batch::Item::<C>::new(vk, sig, msg).unwrap()
            }
            1 => {
                let sk = SigningKey::new(&mut rng);
                let vk = VerifyingKey::<C>::from(&sk);
                let msg = b"BatchVerifyTest";
                let sig = sk.sign(&mut rng, &msg[..]);
                batch::Item::<C>::new(vk, sig, msg).unwrap()
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

/// Test if the empty batch fails to validate.
/// Test case from NCC audit.
pub fn empty_batch_verify<C: Ciphersuite, R: RngCore + CryptoRng>(rng: R) {
    let batch = batch::Verifier::<C>::new();
    assert!(batch.verify(rng).is_err());
}
