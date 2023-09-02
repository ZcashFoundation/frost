#![cfg(feature = "serde")]

mod helpers;

use frost_ed448::SigningKey;
use helpers::samples;
use rand::thread_rng;

#[allow(clippy::unnecessary_literal_unwrap)]
fn check_common_traits_for_type<T: Clone + Eq + PartialEq + std::fmt::Debug>(v: T) {
    // Make sure can be debug-printed. This also catches if the Debug does not
    // have an endless recursion (a popular mistake).
    println!("{:?}", v);
    // Test Clone and Eq
    assert_eq!(v, v.clone());
    // Make sure it can be unwrapped in a Result (which requires Debug).
    let e: Result<T, ()> = Ok(v.clone());
    assert_eq!(v, e.unwrap());
}

#[test]
fn check_signing_key_common_traits() {
    let mut rng = thread_rng();
    let signing_key = SigningKey::new(&mut rng);
    check_common_traits_for_type(signing_key);
}

#[test]
fn check_signing_commitments_common_traits() {
    let commitments = samples::signing_commitments();
    check_common_traits_for_type(commitments);
}

#[test]
fn check_signing_package_common_traits() {
    let signing_package = samples::signing_package();
    check_common_traits_for_type(signing_package);
}

#[test]
fn check_signature_share_common_traits() {
    let signature_share = samples::signature_share();
    check_common_traits_for_type(signature_share);
}

#[test]
fn check_secret_share_common_traits() {
    let secret_share = samples::secret_share();
    check_common_traits_for_type(secret_share);
}

#[test]
fn check_key_package_common_traits() {
    let key_package = samples::key_package();
    check_common_traits_for_type(key_package);
}

#[test]
fn check_public_key_package_common_traits() {
    let public_key_package = samples::public_key_package();
    check_common_traits_for_type(public_key_package);
}

#[test]
fn check_round1_package_common_traits() {
    let round1_package = samples::round1_package();
    check_common_traits_for_type(round1_package);
}

#[test]
fn check_round2_package_common_traits() {
    let round2_package = samples::round2_package();
    check_common_traits_for_type(round2_package);
}
