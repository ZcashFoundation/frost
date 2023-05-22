use ed448_goldilocks::curve::ExtendedPoint;

use frost_ed448::*;
use lazy_static::lazy_static;
use rand::thread_rng;
use serde_json::Value;

#[test]
fn check_sign_with_dealer() {
    let rng = thread_rng();

    frost_core::tests::check_sign_with_dealer::<Ed448Shake256, _>(rng);
}

#[test]
fn check_sign_with_dkg() {
    let rng = thread_rng();

    frost_core::tests::check_sign_with_dkg::<Ed448Shake256, _>(rng);
}

// TODO: make batching work for larger scalars
// #[test]
#[allow(unused)]
fn check_batch_verify() {
    let rng = thread_rng();

    frost_core::tests::batch::batch_verify::<Ed448Shake256, _>(rng);
}

// TODO: make batching work for larger scalars
// #[test]
#[allow(unused)]
fn check_bad_batch_verify() {
    let rng = thread_rng();

    frost_core::tests::batch::bad_batch_verify::<Ed448Shake256, _>(rng);
}

#[test]
fn check_deserialize_identity() {
    let encoded_identity = ExtendedPoint::identity().compress().0;

    let r = <Ed448Shake256 as Ciphersuite>::Group::deserialize(&encoded_identity);
    assert_eq!(r, Err(GroupError::InvalidIdentityElement));
}

#[test]
fn check_deserialize_non_canonical() {
    let mut encoded_generator = ExtendedPoint::generator().compress().0;

    let r = <Ed448Shake256 as Ciphersuite>::Group::deserialize(&encoded_generator);
    assert!(r.is_ok());

    // The last byte only should have the sign bit. Set all other bits to
    // create a non-canonical encoding.
    encoded_generator[56] |= 0x7f;
    let r = <Ed448Shake256 as Ciphersuite>::Group::deserialize(&encoded_generator);
    assert_eq!(r, Err(GroupError::MalformedElement));

    // Besides the last byte, it is still possible to get non-canonical encodings.
    // This is y = p + 19 which is non-canonical and maps to a valid prime-order point.
    let encoded_point = hex::decode("12000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00").unwrap().try_into().unwrap();
    let r = <Ed448Shake256 as Ciphersuite>::Group::deserialize(&encoded_point);
    assert_eq!(r, Err(GroupError::MalformedElement));
}

#[test]
fn check_deserialize_non_prime_order() {
    let encoded_point =
        hex::decode("030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .try_into()
            .unwrap();
    let r = <Ed448Shake256 as Ciphersuite>::Group::deserialize(&encoded_point);
    assert_eq!(r, Err(GroupError::InvalidNonPrimeOrderElement));
}

#[test]
fn check_repair_share_step_1() {
    let rng = thread_rng();

    frost_core::tests::repairable::check_repair_share_step_1::<Ed448Shake256, _>(rng);
}

lazy_static! {
    pub static ref REPAIR_SHARE: Value =
        serde_json::from_str(include_str!("repair-share.json").trim()).unwrap();
}

#[test]
fn check_repair_share_step_2() {
    frost_core::tests::repairable::check_repair_share_step_2::<Ed448Shake256>(&REPAIR_SHARE);
}

#[test]
fn check_repair_share() {
    let rng = thread_rng();
    frost_core::tests::repairable::check_repair_share_step_3::<Ed448Shake256, _>(
        rng,
        &REPAIR_SHARE,
    );
}

#[test]
fn check_rts() {
    let rng = thread_rng();

    frost_core::tests::repairable::check_rts::<Ed448Shake256, _>(rng);
}

#[test]
fn check_create_coefficient_commitment() {
    let valid_element = "b80c392a8ca666c6ee884b6f5a79481cec55a9d7f474918956bf2faedd01ef86be2588aa7526893e67e787db3fd7f2a40ab7c5c76fd9229100";

    frost_core::tests::check_create_coefficient_commitment::<Ed448Shake256>(valid_element);

    let invalid_element = "1234562a8ca666c6ee884b6f5a79481cec55a9d7f474918956bf2faedd01ef86be2588aa7526893e67e787db3fd7f2a40ab7c5c76fd9229100";

    frost_core::tests::check_create_coefficient_commitment_error::<Ed448Shake256>(invalid_element);
}

#[test]
fn check_get_value_of_coefficient_commitment() {
    let rng = thread_rng();

    frost_core::tests::check_get_value_of_coefficient_commitment::<Ed448Shake256, _>(rng);
}

lazy_static! {
    pub static ref ELEMENTS: Value =
        serde_json::from_str(include_str!("elements.json").trim()).unwrap();
}

#[test]
fn check_serialize_vss_commitment() {
    frost_core::tests::check_serialize_vss_commitment::<Ed448Shake256>(&ELEMENTS);
}
