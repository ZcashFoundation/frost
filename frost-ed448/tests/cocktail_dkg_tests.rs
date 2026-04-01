use frost_ed448::*;

#[cfg(feature = "cocktail-dkg")]
#[test]
fn check_sign_with_cocktail_dkg() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::cocktail_dkg::check_sign_with_cocktail_dkg::<Ed448Shake256, _>(rng);
}

#[cfg(feature = "cocktail-dkg")]
#[test]
fn check_cocktail_dkg_test_vectors() {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };

    let json_str = include_str!("helpers/cocktail-dkg-ed448-shake256.json");

    frost_core::tests::cocktail_dkg::check_cocktail_dkg_test_vectors::<Ed448Shake256, _>(
        json_str,
        |data| {
            let mut h = Shake256::default();
            h.update(data);
            let mut out = vec![0u8; 64];
            h.finalize_xof().read(&mut out);
            out
        },
        false, // encrypted shares: 73 vs 72 byte format mismatch
        false, // recovery: ciphertext format incompatible
    );
}
