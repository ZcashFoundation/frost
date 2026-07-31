//! Cross-ciphersuite regression tests proving that the core derivation API is
//! not tied to Bitcoin, Solana, or one concrete curve.

use std::{collections::BTreeMap, marker::PhantomData};

use frost_core::{
    Ciphersuite, SigningPackage,
    keys::{KeyPackage, generate_with_dealer},
};
use frost_hd::{
    DerivationContext, DerivationKey, DerivationPath, DerivationProfile, HdRootKeyPackage,
    HdRootPublicKeyPackage, PathSegment,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const ROOT_DERIVATION_KEY: DerivationKey = DerivationKey::new([
    0x42, 0x19, 0x77, 0x2a, 0xd3, 0x05, 0x94, 0xee, 0x50, 0x68, 0xa1, 0xc4, 0x7b, 0x11,
    0x39, 0xfa, 0x08, 0x6d, 0x25, 0xb0, 0x9e, 0x3c, 0xf2, 0x61, 0x88, 0x0a, 0x57, 0x9b,
    0xcd, 0x31, 0x74, 0xe6,
]);
const MESSAGE: &[u8] = b"generic FROST-HD ciphersuite test";

#[derive(Clone, Copy, Debug)]
struct TestH1Profile<C>(PhantomData<C>);

impl<C: Ciphersuite> DerivationProfile<C> for TestH1Profile<C> {
    const ID: &'static str = "FROST-HD-v1/test-h1-profile";

    fn hash_to_scalar(input: &[u8]) -> frost_core::Scalar<C> {
        C::H1(input)
    }
}

fn context<C: Ciphersuite>() -> frost_hd::ContextDigest {
    DerivationContext::new(
        b"org.example.threshold-wallet".to_vec(),
        b"test-network".to_vec(),
        b"interoperability".to_vec(),
    )
    .expect("bounded context")
    .digest::<C, TestH1Profile<C>>()
    .expect("ciphersuite-bound context digest")
}

fn check_configuration<C: Ciphersuite + PartialEq>(max_signers: u16, min_signers: u16) {
    let seed = [
        max_signers as u8,
        min_signers as u8,
        7,
        9,
        11,
        13,
        17,
        19,
        23,
        29,
        31,
        37,
        41,
        43,
        47,
        53,
        59,
        61,
        67,
        71,
        73,
        79,
        83,
        89,
        97,
        101,
        103,
        107,
        109,
        113,
        127,
        131,
    ];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (shares, public_package) = generate_with_dealer::<C, _>(
        max_signers,
        min_signers,
        frost_core::keys::IdentifierList::Default,
        &mut rng,
    )
    .expect("dealer generation");

    let context = context::<C>();
    let root_public =
        HdRootPublicKeyPackage::<C, TestH1Profile<C>>::new(public_package.clone(), ROOT_DERIVATION_KEY, context);
    let path: DerivationPath = "m/1/42/7".parse().expect("canonical path");
    let derived_public = root_public
        .derive_path(&path)
        .expect("public derivation");

    let mut derived_private = BTreeMap::new();
    for (identifier, share) in shares {
        let key_package = KeyPackage::try_from(share).expect("valid dealer share");
        let root = HdRootKeyPackage::<C, TestH1Profile<C>>::new(key_package, ROOT_DERIVATION_KEY, context)
            .expect("internally consistent root package");
        let direct = root.derive_path(&path).expect("private derivation");

        let first_path: DerivationPath = "m/1".parse().expect("canonical path");
        let stepwise = root
            .derive_path(&first_path)
            .expect("first edge")
            .derive_child(PathSegment::Normal(42))
            .expect("second edge")
            .derive_child(PathSegment::Normal(7))
            .expect("third edge");
        assert_eq!(direct.key_package(), stepwise.key_package());
        assert_eq!(direct.path(), stepwise.path());
        direct
            .matches_public(&derived_public)
            .expect("private and public derivation agree");
        derived_private.insert(identifier, direct);
    }

    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for identifier in derived_private.keys().take(min_signers as usize) {
        let package = derived_private.get(identifier).expect("known participant");
        let (nonce, commitment) =
            frost_core::round1::commit(package.key_package().signing_share(), &mut rng);
        nonces.insert(*identifier, nonce);
        commitments.insert(*identifier, commitment);
    }

    let signing_package = SigningPackage::new(commitments, MESSAGE);
    let mut signature_shares = BTreeMap::new();
    for (identifier, nonce) in &nonces {
        let key_package = derived_private
            .get(identifier)
            .expect("known participant")
            .key_package();
        let signature_share = frost_core::round2::sign(&signing_package, nonce, key_package)
            .expect("derived signature share");
        signature_shares.insert(*identifier, signature_share);
    }

    let signature = frost_core::aggregate(
        &signing_package,
        &signature_shares,
        derived_public.public_key_package(),
    )
    .expect("derived signature aggregation");
    derived_public
        .public_key_package()
        .verifying_key()
        .verify(MESSAGE, &signature)
        .expect("signature verifies under child key");
    assert!(
        public_package
            .verifying_key()
            .verify(MESSAGE, &signature)
            .is_err()
    );
}

#[test]
fn ed25519_supports_multiple_thresholds() {
    check_configuration::<frost_ed25519::Ed25519Sha512>(2, 2);
    check_configuration::<frost_ed25519::Ed25519Sha512>(3, 2);
    check_configuration::<frost_ed25519::Ed25519Sha512>(5, 3);
}

#[test]
fn ristretto255_uses_the_same_generic_protocol() {
    check_configuration::<frost_ristretto255::Ristretto255Sha512>(5, 3);
}

#[test]
fn secp256k1_uses_the_same_generic_protocol_without_bip32() {
    check_configuration::<frost_secp256k1::Secp256K1Sha256>(3, 2);
}
