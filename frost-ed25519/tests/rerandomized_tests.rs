use frost_ed25519::Ed25519Sha512;
use rand::thread_rng;

#[test]
fn check_randomized_sign_with_dealer() {
    let rng = thread_rng();

    let (_msg, _group_signature, _group_pubkey) =
        frost_rerandomized::tests::check_randomized_sign_with_dealer::<Ed25519Sha512, _>(rng);
}
