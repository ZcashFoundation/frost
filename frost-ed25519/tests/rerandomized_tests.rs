use frost_ed25519::Ed25519Sha512;
use rand_core::TryRngCore;

#[test]
fn check_randomized_sign_with_dealer() {
    let rng = rand::rngs::OsRng.unwrap_err();

    let (_msg, _group_signature, _group_pubkey) =
        frost_rerandomized::tests::check_randomized_sign_with_dealer::<Ed25519Sha512, _>(rng);
}
