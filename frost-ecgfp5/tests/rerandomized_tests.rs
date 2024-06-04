use frost_ecgfp5::EcGFp5Poseidon256;
use rand::thread_rng;

#[test]
fn check_randomized_sign_with_dealer() {
    let rng = thread_rng();

    let (_msg, _group_signature, _group_pubkey) =
        frost_rerandomized::tests::check_randomized_sign_with_dealer::<EcGFp5Poseidon256, _>(rng);
}
