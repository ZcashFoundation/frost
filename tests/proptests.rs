use std::convert::TryFrom;

use proptest::prelude::*;
use rand_core::{CryptoRng, RngCore};

use redjubjub_zebra as rjj;

use rjj::{PublicKey, PublicKeyBytes, SecretKey, SigType, Signature};

/// A signature test-case, containing signature data and expected validity.
#[derive(Clone, Debug)]
struct SignatureCase<T: SigType> {
    msg: Vec<u8>,
    sig: Signature<T>,
    pk_bytes: PublicKeyBytes<T>,
    is_valid: bool,
}

impl<T: SigType> SignatureCase<T> {
    fn new<R: RngCore + CryptoRng>(mut rng: R, msg: Vec<u8>) -> Self {
        let sk = SecretKey::new(&mut rng);
        let sig = sk.sign(&mut rng, &msg);
        let pk_bytes = PublicKey::from(&sk).into();
        Self {
            msg,
            sig,
            pk_bytes,
            is_valid: true,
        }
    }

    // Check that signature verification succeeds or fails, as expected.
    fn check(&self) -> bool {
        // The signature data is stored in (refined) byte types, but do a round trip
        // conversion to raw bytes to exercise those code paths.
        let sig = {
            let bytes: [u8; 64] = self.sig.into();
            Signature::<T>::from(bytes)
        };
        let pk_bytes = {
            let bytes: [u8; 32] = self.pk_bytes.into();
            PublicKeyBytes::<T>::from(bytes)
        };

        // Check that signature validation has the expected result.
        self.is_valid
            == PublicKey::try_from(pk_bytes)
                .and_then(|pk| pk.verify(&self.msg, &sig))
                .is_ok()
    }
}

#[derive(Copy, Clone, Debug)]
enum Tweak {
    None,
    ChangeMessage,
}

impl Tweak {
    fn apply<T: SigType>(&self, case: SignatureCase<T>) -> SignatureCase<T> {
        use Tweak::*;
        let SignatureCase {
            mut msg,
            sig,
            pk_bytes,
            is_valid,
        } = case;
        match (self, is_valid) {
            (None, is_valid) => {
                // This is a no-op, so return the original case.
                SignatureCase {
                    msg,
                    sig,
                    pk_bytes,
                    is_valid,
                }
            }
            (ChangeMessage, _) => {
                // Changing the message makes the signature invalid.
                msg.push(90);
                SignatureCase {
                    msg,
                    sig,
                    pk_bytes,
                    is_valid: false,
                }
            }
        }
    }
}

fn tweak_strategy() -> impl Strategy<Value = Tweak> {
    prop_oneof![
        10 => Just(Tweak::None),
        1 => Just(Tweak::ChangeMessage),
    ]
}

proptest! {
    #[test]
    fn tweak_signature(
        tweaks in prop::collection::vec(tweak_strategy(), (0,5)),
        rng_seed in any::<u64>(),
    ) {
        use rjj::{Binding, SpendAuth, };
        use rand_core::SeedableRng;

        // Use a deterministic RNG so that test failures can be reproduced.
        // Seeding with 64 bits of entropy is INSECURE and this code should
        // not be copied outside of this test!
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(rng_seed);

        // Create a test case for each signature type.
        let msg = b"test message for proptests";
        let mut binding = SignatureCase::<Binding>::new(&mut rng, msg.to_vec());
        let mut spendauth = SignatureCase::<SpendAuth>::new(&mut rng, msg.to_vec());

        // Apply tweaks to each case.
        for tweak in &tweaks {
            binding = tweak.apply(binding);
            spendauth = tweak.apply(spendauth);
        }

        assert!(binding.check());
        assert!(spendauth.check());
    }
}
