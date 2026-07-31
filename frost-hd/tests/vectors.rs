#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use frost_core::VerifyingKey;
use frost_ed25519::Ed25519Sha512;
use frost_hd::{
    DerivationContext, DerivationKey, DerivationPath, DerivationProfile,
    HdRootPublicKeyPackage,
};

#[derive(Clone, Copy, Debug)]
struct Ed25519VectorProfile;

impl DerivationProfile<Ed25519Sha512> for Ed25519VectorProfile {
    const ID: &'static str = "FROST-HD-ED25519-SHA512-H1-v1";

    fn hash_to_scalar(input: &[u8]) -> frost_core::Scalar<Ed25519Sha512> {
        <Ed25519Sha512 as frost_core::Ciphersuite>::H1(input)
    }
}

fn decode_32(input: &str) -> [u8; 32] {
    hex::decode(input).unwrap().try_into().unwrap()
}

#[test]
fn matches_independent_ed25519_vector_for_m_0() {
    let root_key = VerifyingKey::<Ed25519Sha512>::deserialize(&decode_32(
        "dc13105f01bc23b21759ff565c4b2f8fdfcbad0f8bd8cad803fe8e5e8342d2de",
    ))
    .unwrap();
    let public_package =
        frost_core::keys::PublicKeyPackage::new(BTreeMap::new(), root_key, None);
    let context = DerivationContext::new(
        b"org.example.wallet".to_vec(),
        b"solana-devnet".to_vec(),
        b"threshold-child-keys".to_vec(),
    )
    .unwrap()
    .digest::<Ed25519Sha512, Ed25519VectorProfile>()
    .unwrap();
    assert_eq!(
        context.to_bytes(),
        decode_32("6ce4bd89a780a01736e4e7f008f8b3a0a39b20397580898f5bc95489e8d60c53")
    );

    let root = HdRootPublicKeyPackage::<Ed25519Sha512, Ed25519VectorProfile>::new(
        public_package,
        DerivationKey::new(decode_32(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )),
        context,
    );
    let child = root
        .derive_path(&"m/0".parse::<DerivationPath>().unwrap())
        .unwrap();

    assert_eq!(
        child.public_key_package().verifying_key().serialize().unwrap(),
        decode_32("6b31d60dbbd186e38aac90a020c5ae969135dd4d0b3314b36a5affe60ae913cf")
    );
    assert_eq!(
        child.derivation_key().to_bytes(),
        decode_32("b84dc1c3fa2ae0c3572ca0c75131981f1202124b24775ff40a3a0f967e8df598")
    );
}
