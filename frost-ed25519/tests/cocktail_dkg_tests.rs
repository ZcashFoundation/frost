use frost_ed25519::*;

#[cfg(feature = "cocktail-dkg")]
#[test]
fn check_sign_with_cocktail_dkg() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::cocktail_dkg::check_sign_with_cocktail_dkg::<Ed25519Sha512, _>(rng);
}

#[cfg(feature = "cocktail-dkg")]
#[test]
fn check_cocktail_dkg_test_vectors() {
    use sha2::{Digest, Sha512};

    let json_str = include_str!("helpers/cocktail-dkg-ed25519-sha512.json");

    frost_core::tests::cocktail_dkg::check_cocktail_dkg_test_vectors::<Ed25519Sha512, _>(
        json_str,
        |data| Sha512::digest(data).to_vec(),
        true, // encrypted shares match (XChaCha20Poly1305)
        true, // recovery is tested
    );
}
