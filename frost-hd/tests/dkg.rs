//! DKG-derived key agreement, Ed25519 interoperability and related-key regressions.

use std::collections::BTreeMap;

use frost_core::{Ciphersuite, Field, Group};
use frost_ed25519 as frost;
use frost_hd::{
    DerivationContext, DerivationKey, DerivationPath, DerivationProfile, Error, HdRootKeyPackage,
    HdRootPublicKeyPackage, MAX_PATH_DEPTH, PathSegment,
};
use hmac::{Hmac, KeyInit, Mac};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::Sha512;

type C = frost::Ed25519Sha512;
type Scalar = frost_core::Scalar<C>;
type Keys = BTreeMap<frost::Identifier, frost::keys::KeyPackage>;

const DERIVATION_KEY: DerivationKey = DerivationKey::new([0x42; 32]);
const MESSAGE: &[u8] = b"FROST-HD DKG-derived child signature";
const ALTERED_MESSAGE: &[u8] = b"altered message";
const APPLICATION: &[u8] = b"org.example.frost-hd";
const NETWORK: &[u8] = b"offline";
const RECEIVE_PURPOSE: &[u8] = b"receive";
const DIFFERENT_PURPOSE: &[u8] = b"spend";
const MATCHING_PATH: &str = "m/1/42";
const DIFFERENT_PATH: &str = "m/1/43";
const DELEGATED_PATH: &str = "m/0";
const SIBLING_PATH: &str = "m/99/3";
const PATHS: [&str; 4] = [DELEGATED_PATH, MATCHING_PATH, "m/7/3/999", "m/4294967295"];
const CASES: [(u16, u16); 3] = [(2, 2), (3, 2), (5, 3)];
const SEEDS: u8 = 4;
const EXPECTED_SIGNATURE_COUNT: usize = 224;
const TRANSCRIPT_VERSION: u16 = 1;
const NORMAL_SEGMENT_KIND: u8 = 0;
const INITIAL_RETRY: u16 = 0;
const DERIVATION_KEY_LENGTH: usize = 32;
const DST_EDGE: &[u8] = b"FROST-HD-v1/edge";
const DST_HASH_TO_SCALAR: &[u8] = b"FROST-HD-v1/hash-to-scalar";
const DST_TWEAK_PRF: &[u8] = b"FROST-HD-v1/tweak-prf";
const DST_CHILD_KEY: &[u8] = b"FROST-HD-v1/child-derivation-key";

#[derive(Clone, Copy, Debug)]
struct Profile;

impl DerivationProfile<C> for Profile {
    const ID: &'static str = "FROST-HD-ED25519-SHA512-H1-v1";

    fn hash_to_scalar(input: &[u8]) -> Scalar {
        C::H1(input)
    }
}

fn context(purpose: &[u8]) -> frost_hd::ContextDigest {
    DerivationContext::new(APPLICATION, NETWORK, purpose)
        .unwrap()
        .digest::<C, Profile>()
        .unwrap()
}

// Each simulated transport boundary uses the actual package serialization.
fn dkg(
    max_signers: u16,
    threshold: u16,
    rng: &mut ChaCha20Rng,
) -> (Keys, frost::keys::PublicKeyPackage) {
    let identifiers: Vec<_> = (1..=max_signers)
        .map(|id| frost::Identifier::try_from(id).unwrap())
        .collect();
    let mut round1_secrets = BTreeMap::new();
    let mut broadcasts = BTreeMap::new();
    for id in &identifiers {
        let (secret, package) =
            frost::keys::dkg::part1(*id, max_signers, threshold, &mut *rng).unwrap();
        round1_secrets.insert(*id, secret);
        broadcasts.insert(
            *id,
            frost::keys::dkg::round1::Package::deserialize(&package.serialize().unwrap()).unwrap(),
        );
    }
    let mut round2_secrets = BTreeMap::new();
    let mut outgoing = BTreeMap::new();
    for id in &identifiers {
        let received = broadcasts
            .iter()
            .filter(|(sender, _)| *sender != id)
            .map(|(sender, package)| (*sender, package.clone()))
            .collect();
        let (secret, packages) =
            frost::keys::dkg::part2(round1_secrets.remove(id).unwrap(), &received).unwrap();
        round2_secrets.insert(*id, secret);
        outgoing.insert(*id, packages);
    }
    let mut keys = BTreeMap::new();
    let mut public = None;
    for id in &identifiers {
        let round1 = broadcasts
            .iter()
            .filter(|(sender, _)| *sender != id)
            .map(|(sender, package)| (*sender, package.clone()))
            .collect();
        let round2 = outgoing
            .iter()
            .filter(|(sender, _)| *sender != id)
            .map(|(sender, packages)| {
                (
                    *sender,
                    frost::keys::dkg::round2::Package::deserialize(
                        &packages[id].serialize().unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect();
        let (key, package) =
            frost::keys::dkg::part3(&round2_secrets[id], &round1, &round2).unwrap();
        if let Some(expected) = &public {
            assert_eq!(&package, expected);
        }
        public = Some(package);
        keys.insert(
            *id,
            frost::keys::KeyPackage::deserialize(&key.serialize().unwrap()).unwrap(),
        );
    }
    let public = public.unwrap();
    (
        keys,
        frost::keys::PublicKeyPackage::deserialize(&public.serialize().unwrap()).unwrap(),
    )
}

fn sign(
    keys: &Keys,
    public: &frost::keys::PublicKeyPackage,
    identifiers: &[frost::Identifier],
    rng: &mut ChaCha20Rng,
) -> Result<frost::Signature, frost::Error> {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in identifiers {
        let (nonce, commitment) = frost::round1::commit(keys[id].signing_share(), &mut *rng);
        nonces.insert(*id, nonce);
        commitments.insert(*id, commitment);
    }
    let package = frost::SigningPackage::new(commitments, MESSAGE);
    let mut shares = BTreeMap::new();
    for id in identifiers {
        shares.insert(*id, frost::round2::sign(&package, &nonces[id], &keys[id])?);
    }
    frost::aggregate(&package, &shares, public)
}

fn external_verify(
    public: &frost::keys::PublicKeyPackage,
    signature: &frost::Signature,
    message: &[u8],
) -> bool {
    let bytes = public
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();
    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap();
    let bytes: [u8; 64] = signature.serialize().unwrap().try_into().unwrap();
    key.verify_strict(message, &ed25519_dalek::Signature::from(bytes))
        .is_ok()
}

#[test]
fn real_dkg_derivation_all_threshold_subsets_and_independent_verification() {
    let mut signature_count = 0;
    for seed in 0..SEEDS {
        for (max_signers, threshold) in CASES {
            let mut rng = ChaCha20Rng::from_seed([seed; 32]);
            let (root_keys, root_public) = dkg(max_signers, threshold, &mut rng);
            let public_root = HdRootPublicKeyPackage::<C, Profile>::new(
                root_public.clone(),
                DERIVATION_KEY,
                context(RECEIVE_PURPOSE),
            );
            let mut seen_keys = Vec::new();
            for path_text in PATHS {
                let path: DerivationPath = path_text.parse().unwrap();
                let public = public_root.derive_path(&path).unwrap();
                assert!(!seen_keys.contains(public.public_key_package().verifying_key()));
                seen_keys.push(*public.public_key_package().verifying_key());
                let mut children = Keys::new();
                for (id, key) in &root_keys {
                    let root = HdRootKeyPackage::<C, Profile>::new(
                        key.clone(),
                        DERIVATION_KEY,
                        context(RECEIVE_PURPOSE),
                    )
                    .unwrap();
                    let child = root.derive_path(&path).unwrap();
                    child.matches_public(&public).unwrap();
                    let mut stepwise = root.derive_child(path.segments()[0].index()).unwrap();
                    for segment in &path.segments()[1..] {
                        stepwise = stepwise.derive_child(*segment).unwrap();
                    }
                    assert_eq!(child.key_package(), stepwise.key_package());
                    assert_eq!(child.derivation_key(), stepwise.derivation_key());
                    children.insert(
                        *id,
                        frost::keys::KeyPackage::deserialize(
                            &child.key_package().serialize().unwrap(),
                        )
                        .unwrap(),
                    );
                }
                let identifiers: Vec<_> = children.keys().copied().collect();
                for mask in 0u32..(1u32 << max_signers) {
                    if mask.count_ones() != u32::from(threshold) {
                        continue;
                    }
                    let subset: Vec<_> = identifiers
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| mask & (1 << index) != 0)
                        .map(|(_, id)| *id)
                        .collect();
                    let signature =
                        sign(&children, public.public_key_package(), &subset, &mut rng).unwrap();
                    public
                        .public_key_package()
                        .verifying_key()
                        .verify(MESSAGE, &signature)
                        .unwrap();
                    assert!(external_verify(
                        public.public_key_package(),
                        &signature,
                        MESSAGE
                    ));
                    assert!(!external_verify(&root_public, &signature, MESSAGE));
                    assert!(!external_verify(
                        public.public_key_package(),
                        &signature,
                        ALTERED_MESSAGE
                    ));
                    signature_count += 1;
                }
                assert!(
                    sign(
                        &children,
                        public.public_key_package(),
                        &identifiers[..usize::from(threshold - 1)],
                        &mut rng
                    )
                    .is_err()
                );
            }
        }
    }
    assert_eq!(signature_count, EXPECTED_SIGNATURE_COUNT);
}

#[test]
fn rejects_mismatched_families_mixed_paths_and_invalid_paths() {
    let mut rng = ChaCha20Rng::from_seed([11; 32]);
    let (keys, public) = dkg(3, 2, &mut rng);
    let root = HdRootPublicKeyPackage::<C, Profile>::new(
        public.clone(),
        DERIVATION_KEY,
        context(RECEIVE_PURPOSE),
    );
    let path: DerivationPath = MATCHING_PATH.parse().unwrap();
    let good = root.derive_path(&path).unwrap();
    let wrong_path = root.derive_path(&DIFFERENT_PATH.parse().unwrap()).unwrap();
    let wrong_context = HdRootPublicKeyPackage::<C, Profile>::new(
        public.clone(),
        DERIVATION_KEY,
        context(DIFFERENT_PURPOSE),
    )
    .derive_path(&path)
    .unwrap();
    let wrong_key = HdRootPublicKeyPackage::<C, Profile>::new(
        public,
        DerivationKey::new([0x43; 32]),
        context(RECEIVE_PURPOSE),
    )
    .derive_path(&path)
    .unwrap();
    let mut children = Keys::new();
    for (id, key) in &keys {
        let private = HdRootKeyPackage::<C, Profile>::new(
            key.clone(),
            DERIVATION_KEY,
            context(RECEIVE_PURPOSE),
        )
        .unwrap();
        let child = private.derive_path(&path).unwrap();
        child.matches_public(&good).unwrap();
        for bad in [&wrong_path, &wrong_context, &wrong_key] {
            assert!(child.matches_public(bad).is_err());
        }
        children.insert(*id, child.key_package().clone());
    }
    let identifiers: Vec<_> = keys.keys().copied().take(2).collect();
    let other = HdRootKeyPackage::<C, Profile>::new(
        keys[&identifiers[1]].clone(),
        DERIVATION_KEY,
        context(RECEIVE_PURPOSE),
    )
    .unwrap()
    .derive_path(&DIFFERENT_PATH.parse().unwrap())
    .unwrap();
    children.insert(identifiers[1], other.key_package().clone());
    assert!(sign(&children, good.public_key_package(), &identifiers, &mut rng).is_err());
    assert!(matches!(
        root.derive_path(&DerivationPath::root()),
        Err(Error::RootPathNotSignable)
    ));
    assert!(matches!(
        root.derive_path(&"m/0'/1".parse().unwrap()),
        Err(Error::HardenedDerivationUnsupported)
    ));
    let deepest = DerivationPath::new(vec![PathSegment::Normal(0); MAX_PATH_DEPTH]).unwrap();
    let child = root.derive_path(&deepest).unwrap();
    assert!(matches!(
        child.derive_child(PathSegment::Normal(0)),
        Err(Error::PathTooDeep)
    ));
    assert!("m/4294967296".parse::<DerivationPath>().is_err());
}

// This separate transcript implementation intentionally does not call the HD KDF.
fn cumulative_tweak(public: &frost::keys::PublicKeyPackage, path: &DerivationPath) -> Scalar {
    fn frame(output: &mut Vec<u8>, bytes: &[u8]) {
        output.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        output.extend_from_slice(bytes);
    }
    fn prf(key: &[u8; DERIVATION_KEY_LENGTH], domain: &[u8], input: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha512>::new_from_slice(key).unwrap();
        mac.update(domain);
        mac.update(input);
        mac.finalize().into_bytes().to_vec()
    }
    let mut point = public.verifying_key().to_element();
    let mut key = DERIVATION_KEY.to_bytes();
    let mut total = <frost::Ed25519ScalarField as Field>::zero();
    for segment in path.segments() {
        let mut common = DST_EDGE.to_vec();
        common.extend_from_slice(&TRANSCRIPT_VERSION.to_be_bytes());
        frame(&mut common, C::ID.as_bytes());
        frame(&mut common, Profile::ID.as_bytes());
        common.extend_from_slice(&context(RECEIVE_PURPOSE).to_bytes());
        frame(
            &mut common,
            &frost_core::VerifyingKey::<C>::new(point)
                .serialize()
                .unwrap(),
        );
        common.push(NORMAL_SEGMENT_KIND);
        common.extend_from_slice(&segment.index().to_be_bytes());
        common.extend_from_slice(&INITIAL_RETRY.to_be_bytes());
        let mut input = DST_HASH_TO_SCALAR.to_vec();
        input.extend_from_slice(&prf(&key, DST_TWEAK_PRF, &common));
        let tweak = C::H1(&input);
        assert_ne!(tweak, <frost::Ed25519ScalarField as Field>::zero());
        point += <<C as Ciphersuite>::Group as Group>::generator() * tweak;
        let next_key = prf(&key, DST_CHILD_KEY, &common);
        key.copy_from_slice(&next_key[..DERIVATION_KEY_LENGTH]);
        total += tweak;
    }
    total
}

#[test]
fn delegated_child_share_recovers_parent_and_signs_a_sibling() {
    let mut rng = ChaCha20Rng::from_seed([12; 32]);
    let (keys, public) = dkg(2, 2, &mut rng);
    let id = *keys.keys().next().unwrap();
    let root = HdRootKeyPackage::<C, Profile>::new(
        keys[&id].clone(),
        DERIVATION_KEY,
        context(RECEIVE_PURPOSE),
    )
    .unwrap();
    let allowed: DerivationPath = DELEGATED_PATH.parse().unwrap();
    let sibling: DerivationPath = SIBLING_PATH.parse().unwrap();
    let delegated = root.derive_path(&allowed).unwrap();
    let recovered =
        delegated.key_package().signing_share().to_scalar() - cumulative_tweak(&public, &allowed);
    assert_eq!(recovered, keys[&id].signing_share().to_scalar());
    let sibling_share = recovered + cumulative_tweak(&public, &sibling);
    assert_eq!(
        sibling_share,
        root.derive_path(&sibling)
            .unwrap()
            .key_package()
            .signing_share()
            .to_scalar()
    );
    let sibling_public =
        HdRootPublicKeyPackage::<C, Profile>::new(public, DERIVATION_KEY, context(RECEIVE_PURPOSE))
            .derive_path(&sibling)
            .unwrap();
    let public = sibling_public.public_key_package();
    let mut sibling_keys = Keys::new();
    for (participant, key) in &keys {
        if *participant == id {
            sibling_keys.insert(
                *participant,
                frost::keys::KeyPackage::new(
                    *participant,
                    frost::keys::SigningShare::new(sibling_share),
                    public.verifying_shares()[participant],
                    *public.verifying_key(),
                    *key.min_signers(),
                ),
            );
        } else {
            let own_root = HdRootKeyPackage::<C, Profile>::new(
                key.clone(),
                DERIVATION_KEY,
                context(RECEIVE_PURPOSE),
            )
            .unwrap();
            sibling_keys.insert(
                *participant,
                own_root
                    .derive_path(&sibling)
                    .unwrap()
                    .key_package()
                    .clone(),
            );
        }
    }
    let participants: Vec<_> = sibling_keys.keys().copied().collect();
    let signature = sign(&sibling_keys, public, &participants, &mut rng).unwrap();
    assert!(external_verify(public, &signature, MESSAGE));
}

// Deliberately non-uniform profiles exercise exceptional branches only.
#[derive(Clone, Copy, Debug)]
struct ZeroProfile;

impl DerivationProfile<C> for ZeroProfile {
    const ID: &'static str = "FROST-HD/test-zero-profile";

    fn hash_to_scalar(_: &[u8]) -> Scalar {
        <frost::Ed25519ScalarField as Field>::zero()
    }
}

#[derive(Clone, Copy, Debug)]
struct OneProfile;

impl DerivationProfile<C> for OneProfile {
    const ID: &'static str = "FROST-HD/test-one-profile";

    fn hash_to_scalar(_: &[u8]) -> Scalar {
        <frost::Ed25519ScalarField as Field>::one()
    }
}

#[test]
fn exceptional_scalars_fail_closed_and_malformed_private_package_is_rejected() {
    let one = <frost::Ed25519ScalarField as Field>::one();
    let generator = <<C as Ciphersuite>::Group as Group>::generator();
    let id = frost::Identifier::try_from(1u16).unwrap();
    let key = frost::keys::KeyPackage::new(
        id,
        frost::keys::SigningShare::new(-one),
        frost::keys::VerifyingShare::new(-generator),
        frost_core::VerifyingKey::new(generator),
        2,
    );
    let zero_context = DerivationContext::new(APPLICATION, NETWORK, b"zero")
        .unwrap()
        .digest::<C, ZeroProfile>()
        .unwrap();
    let zero =
        HdRootKeyPackage::<C, ZeroProfile>::new(key.clone(), DERIVATION_KEY, zero_context).unwrap();
    assert!(matches!(zero.derive_child(0), Err(Error::RetryExhausted)));
    let one_context = DerivationContext::new(APPLICATION, NETWORK, b"one")
        .unwrap()
        .digest::<C, OneProfile>()
        .unwrap();
    let identity_share =
        HdRootKeyPackage::<C, OneProfile>::new(key, DERIVATION_KEY, one_context).unwrap();
    assert!(matches!(
        identity_share.derive_child(0),
        Err(Error::DerivedVerifyingShareIdentity)
    ));
    let invalid = frost::keys::KeyPackage::new(
        id,
        frost::keys::SigningShare::new(one),
        frost::keys::VerifyingShare::new(-generator),
        frost_core::VerifyingKey::new(generator),
        2,
    );
    assert!(matches!(
        HdRootKeyPackage::<C, Profile>::new(invalid, DERIVATION_KEY, context(RECEIVE_PURPOSE)),
        Err(Error::InconsistentPrivatePackage)
    ));
}
