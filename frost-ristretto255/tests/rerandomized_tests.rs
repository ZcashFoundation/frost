use frost_ristretto255::Ristretto255Sha512;
use rand_core::TryRngCore;

#[test]
fn check_randomized_sign_with_dealer() {
    let rng = rand::rngs::OsRng.unwrap_err();

    let (_msg, _group_signature, _group_pubkey) =
        frost_rerandomized::tests::check_randomized_sign_with_dealer::<Ristretto255Sha512, _>(rng);
}
