use frost_secp256k1::Secp256K1Sha256;
use rand::thread_rng;

#[test]
fn check_randomized_sign_with_dealer() {
    let rng = thread_rng();

    let (_msg, _group_signature, _group_pubkey) =
        frost_rerandomized::tests::check_randomized_sign_with_dealer::<Secp256K1Sha256, _>(rng);
}
