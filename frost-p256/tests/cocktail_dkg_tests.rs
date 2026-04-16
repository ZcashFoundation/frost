use frost_p256::*;

#[cfg(feature = "cocktail-dkg")]
#[test]
fn check_sign_with_cocktail_dkg() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::cocktail_dkg::check_sign_with_cocktail_dkg::<P256Sha256, _>(rng);
}

#[cfg(feature = "cocktail-dkg")]
#[test]
fn check_cocktail_dkg_test_vectors() {
    use sha2::{Digest, Sha256};

    let json_str = include_str!("helpers/cocktail-dkg-p256-sha256.json");

    frost_core::tests::cocktail_dkg::check_cocktail_dkg_test_vectors::<P256Sha256, _>(
        json_str,
        |data| Sha256::digest(data).to_vec(),
        true, // encrypted shares match (XAES-256-GCM)
        true, // recovery is tested
    );
}
