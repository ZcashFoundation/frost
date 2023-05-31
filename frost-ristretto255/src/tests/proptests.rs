use crate::*;
use frost_core::tests::proptests::{tweak_strategy, SignatureCase};
use proptest::prelude::*;

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
        let rng = ChaChaRng::from_seed(rng_seed);

        // Create a test case for each signature type.
        let msg = b"test message for proptests";
        let mut sig = SignatureCase::<Ristretto255Sha512>::new(rng, msg.to_vec());

        // Apply tweaks to each case.
        for t in &tweaks {
            sig.apply_tweak(t);
        }

        assert!(sig.check());
    }


}
