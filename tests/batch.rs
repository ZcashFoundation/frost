use rand::thread_rng;

use redjubjub::*;

#[test]
fn spendauth_batch_verify() {
    let rng = thread_rng();
    let mut batch = batch::Verifier::new();
    for _ in 0..32 {
        let sk = SigningKey::<SpendAuth>::new(rng);
        let vk = VerificationKey::from(&sk);
        let msg = b"BatchVerifyTest";
        let sig = sk.sign(rng, &msg[..]);
        batch.queue((vk.into(), sig, msg));
    }
    assert!(batch.verify(rng).is_ok());
}

#[test]
fn binding_batch_verify() {
    let rng = thread_rng();
    let mut batch = batch::Verifier::new();
    for _ in 0..32 {
        let sk = SigningKey::<SpendAuth>::new(rng);
        let vk = VerificationKey::from(&sk);
        let msg = b"BatchVerifyTest";
        let sig = sk.sign(rng, &msg[..]);
        batch.queue((vk.into(), sig, msg));
    }
    assert!(batch.verify(rng).is_ok());
}

#[test]
fn alternating_batch_verify() {
    let rng = thread_rng();
    let mut batch = batch::Verifier::new();
    for i in 0..32 {
        match i % 2 {
            0 => {
                let sk = SigningKey::<SpendAuth>::new(rng);
                let vk = VerificationKey::from(&sk);
                let msg = b"BatchVerifyTest";
                let sig = sk.sign(rng, &msg[..]);
                batch.queue((vk.into(), sig, msg));
            }
            1 => {
                let sk = SigningKey::<Binding>::new(rng);
                let vk = VerificationKey::from(&sk);
                let msg = b"BatchVerifyTest";
                let sig = sk.sign(rng, &msg[..]);
                batch.queue((vk.into(), sig, msg));
            }
            _ => panic!(),
        }
    }
    assert!(batch.verify(rng).is_ok());
}
