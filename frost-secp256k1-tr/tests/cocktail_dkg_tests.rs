use frost_secp256k1_tr::*;

#[cfg(feature = "cocktail-dkg")]
#[test]
fn check_sign_with_cocktail_dkg() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::cocktail_dkg::check_sign_with_cocktail_dkg::<Secp256K1Sha256TR, _>(
        rng,
    );
}

#[cfg(feature = "cocktail-dkg")]
#[test]
fn check_cocktail_dkg_test_vectors() {
    use sha2::{Digest, Sha256};

    let json_str = include_str!("helpers/cocktail-dkg-secp256k1-sha256.json");

    frost_core::tests::cocktail_dkg::check_cocktail_dkg_test_vectors::<Secp256K1Sha256TR, _>(
        json_str,
        |data| Sha256::digest(data).to_vec(),
        true, // encrypted shares match (XAES-256-GCM)
        true, // recovery is tested
    );
}
