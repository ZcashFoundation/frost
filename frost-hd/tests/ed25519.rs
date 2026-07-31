use std::collections::BTreeMap;

use frost_ed25519 as frost;
use frost_hd::{
    DerivationContext, DerivationKey, DerivationPath, DerivationProfile, Error,
    HdRootKeyPackage, HdRootPublicKeyPackage, PathSegment,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[derive(Clone, Copy, Debug)]
struct Ed25519H1Profile;

impl DerivationProfile<frost::Ed25519Sha512> for Ed25519H1Profile {
    const ID: &'static str = "FROST-HD-ED25519-SHA512-H1-v1";

    fn hash_to_scalar(input: &[u8]) -> frost_core::Scalar<frost::Ed25519Sha512> {
        <frost::Ed25519Sha512 as frost_core::Ciphersuite>::H1(input)
    }
}

fn sign_child(
    key_packages: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public_key_package: &frost::keys::PublicKeyPackage,
    threshold: u16,
    rng: &mut ChaCha20Rng,
) {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for identifier in key_packages.keys().take(threshold as usize) {
        let (nonce, commitment) =
            frost::round1::commit(key_packages[identifier].signing_share(), &mut *rng);
        nonces.insert(*identifier, nonce);
        commitments.insert(*identifier, commitment);
    }
    let message = b"generic FROST-HD child signature";
    let signing_package = frost::SigningPackage::new(commitments, message);
    let mut signature_shares = BTreeMap::new();
    for (identifier, nonce) in &nonces {
        signature_shares.insert(
            *identifier,
            frost::round2::sign(&signing_package, nonce, &key_packages[identifier])
                .expect("valid child signature share"),
        );
    }
    let signature = frost::aggregate(&signing_package, &signature_shares, public_key_package)
        .expect("valid aggregate signature");
    public_key_package
        .verifying_key()
        .verify(message, &signature)
        .expect("child signature verifies");
}

fn run_threshold_case(max_signers: u16, threshold: u16, seed: u8) {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let (shares, root_public_package) = frost::keys::generate_with_dealer(
        max_signers,
        threshold,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .expect("root key generation");
    let root_packages: BTreeMap<_, _> = shares
        .into_iter()
        .map(|(identifier, share)| {
            (
                identifier,
                frost::keys::KeyPackage::try_from(share).expect("valid root share"),
            )
        })
        .collect();

    let context = DerivationContext::new(
        b"org.example.wallet".to_vec(),
        b"test-network".to_vec(),
        b"receive".to_vec(),
    )
    .expect("valid context")
    .digest::<frost::Ed25519Sha512, Ed25519H1Profile>()
    .expect("context digest");
    let derivation_key = DerivationKey::new([0x42; 32]);
    let public_root =
        HdRootPublicKeyPackage::<frost::Ed25519Sha512, Ed25519H1Profile>::new(root_public_package.clone(), derivation_key, context);

    for path_text in ["m/0", "m/1/42", "m/7/3/999"] {
        let path: DerivationPath = path_text.parse().expect("canonical path");
        let child_public = public_root.derive_path(&path).expect("public derivation");
        let mut child_key_packages = BTreeMap::new();
        for (identifier, root_package) in &root_packages {
            let root = HdRootKeyPackage::<frost::Ed25519Sha512, Ed25519H1Profile>::new(root_package.clone(), derivation_key, context)
                .expect("valid private root");
            let child = root.derive_path(&path).expect("private derivation");
            child
                .matches_public(&child_public)
                .expect("private/public agreement");
            child_key_packages.insert(*identifier, child.key_package().clone());
        }
        sign_child(
            &child_key_packages,
            child_public.public_key_package(),
            threshold,
            &mut rng,
        );
    }

    let direct = public_root.derive_path(&"m/1/42".parse().unwrap()).unwrap();
    let stepwise = public_root
        .derive_child(1)
        .unwrap()
        .derive_child(PathSegment::Normal(42))
        .unwrap();
    assert_eq!(
        direct.public_key_package().verifying_key(),
        stepwise.public_key_package().verifying_key()
    );
    assert_eq!(direct.derivation_key(), stepwise.derivation_key());
}

#[test]
fn derives_and_signs_ed25519_2_of_2() {
    run_threshold_case(2, 2, 1);
}

#[test]
fn derives_and_signs_ed25519_2_of_3() {
    run_threshold_case(3, 2, 2);
}

#[test]
fn derives_and_signs_ed25519_3_of_5() {
    run_threshold_case(5, 3, 3);
}

#[test]
fn hardened_segments_are_explicitly_rejected() {
    let mut rng = ChaCha20Rng::from_seed([9; 32]);
    let (_, root_public) = frost::keys::generate_with_dealer(
        2,
        2,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();
    let context = DerivationContext::new(b"app".to_vec(), b"net".to_vec(), b"purpose".to_vec())
        .unwrap()
        .digest::<frost::Ed25519Sha512, Ed25519H1Profile>()
        .unwrap();
    let root = HdRootPublicKeyPackage::<frost::Ed25519Sha512, Ed25519H1Profile>::new(root_public, DerivationKey::new([7; 32]), context);
    assert!(matches!(
        root.derive_path(&"m/0'/1".parse().unwrap()),
        Err(Error::HardenedDerivationUnsupported)
    ));
}

#[test]
fn root_path_cannot_be_exposed_as_a_signable_child() {
    let mut rng = ChaCha20Rng::from_seed([10; 32]);
    let (_, root_public) = frost::keys::generate_with_dealer(
        2,
        2,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();
    let context = DerivationContext::new(b"app".to_vec(), b"net".to_vec(), b"purpose".to_vec())
        .unwrap()
        .digest::<frost::Ed25519Sha512, Ed25519H1Profile>()
        .unwrap();
    let root = HdRootPublicKeyPackage::<frost::Ed25519Sha512, Ed25519H1Profile>::new(root_public, DerivationKey::new([8; 32]), context);
    assert!(matches!(
        root.derive_path(&DerivationPath::root()),
        Err(Error::RootPathNotSignable)
    ));
}
