use frost_p256::*;
use proptest::prelude::*;
use rand_core::{CryptoRng, RngCore};

/// A signature test-case, containing signature data and expected validity.
#[derive(Clone, Debug)]
struct SignatureCase {
    msg: Vec<u8>,
    sig: Signature,
    vk: VerifyingKey,
    invalid_vk: VerifyingKey,
    is_valid: bool,
}

/// A modification to a test-case.
#[derive(Copy, Clone, Debug)]
enum Tweak {
    /// No-op, used to check that unchanged cases verify.
    None,
    /// Change the message the signature is defined for, invalidating the signature.
    ChangeMessage,
    /// Change the public key the signature is defined for, invalidating the signature.
    ChangePubkey,
    /* XXX implement this -- needs to regenerate a custom signature because the
       nonce commitment is fed into the hash, so it has to have torsion at signing
       time.
    /// Change the case to have a torsion component in the signature's `r` value.
    AddTorsion,
    */
    /* XXX implement this -- needs custom handling of field arithmetic.
    /// Change the signature's `s` scalar to be unreduced (mod L), invalidating the signature.
    UnreducedScalar,
    */
}

impl SignatureCase {
    fn new<R: RngCore + CryptoRng>(mut rng: R, msg: Vec<u8>) -> Self {
        let sk = SigningKey::new(&mut rng);
        let sig = sk.sign(&mut rng, &msg);
        let vk = VerifyingKey::from(&sk);
        let invalid_vk = VerifyingKey::from(&SigningKey::new(&mut rng));
        Self {
            msg,
            sig,
            vk,
            invalid_vk,
            is_valid: true,
        }
    }

    // Check that signature verification succeeds or fails, as expected.
    fn check(&self) -> bool {
        // The signature data is stored in (refined) byte types, but do a round trip
        // conversion to raw bytes to exercise those code paths.
        let _sig = {
            let bytes = self.sig.to_bytes();
            Signature::from_bytes(bytes)
        };

        // Check that the verification key is a valid key.
        let _pub_key = VerifyingKey::from_bytes(self.vk.to_bytes())
            .expect("The test verification key to be well-formed.");

        // Check that signature validation has the expected result.
        self.is_valid == self.vk.verify(&self.msg, &self.sig).is_ok()
    }

    fn apply_tweak(&mut self, tweak: &Tweak) {
        match tweak {
            Tweak::None => {}
            Tweak::ChangeMessage => {
                // Changing the message makes the signature invalid.
                self.msg.push(90);
                self.is_valid = false;
            }
            Tweak::ChangePubkey => {
                // Changing the public key makes the signature invalid.
                self.vk = self.invalid_vk;
                self.is_valid = false;
            }
        }
    }
}

fn tweak_strategy() -> impl Strategy<Value = Tweak> {
    prop_oneof![
        10 => Just(Tweak::None),
        1 => Just(Tweak::ChangeMessage),
        1 => Just(Tweak::ChangePubkey),
    ]
}

use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

proptest! {

    #[test]
    fn tweak_signature(
        tweaks in prop::collection::vec(tweak_strategy(), (0,5)),
        rng_seed in prop::array::uniform32(any::<u8>()),
    ) {
        // Use a deterministic RNG so that test failures can be reproduced.
        // Seeding with 64 bits of entropy is INSECURE and this code should
        // not be copied outside of this test!
        let mut rng = ChaChaRng::from_seed(rng_seed);

        // Create a test case for each signature type.
        let msg = b"test message for proptests";
        let mut sig = SignatureCase::new(&mut rng, msg.to_vec());

        // Apply tweaks to each case.
        for t in &tweaks {
            sig.apply_tweak(t);
        }

        assert!(sig.check());
    }


}
