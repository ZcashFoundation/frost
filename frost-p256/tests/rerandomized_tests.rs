use frost_p256::P256Sha256;
use rand_core::TryRngCore;

#[test]
fn check_randomized_sign_with_dealer() {
    let rng = rand::rngs::OsRng.unwrap_err();

    let (_msg, _group_signature, _group_pubkey) =
        frost_rerandomized::tests::check_randomized_sign_with_dealer::<P256Sha256, _>(rng);
}
