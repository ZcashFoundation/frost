use ed448_goldilocks::curve::ExtendedPoint;
use frost_core::{Ciphersuite, Group};
use frost_ed448::*;
use rand::thread_rng;

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

    let r = <<Ed448Shake256 as Ciphersuite>::Group as Group>::deserialize(&encoded_identity);
    assert_eq!(r, Err(Error::InvalidIdentityElement));
}

#[test]
fn check_deserialize_non_canonical() {
    let mut encoded_generator = ExtendedPoint::generator().compress().0;

    let r = <<Ed448Shake256 as Ciphersuite>::Group as Group>::deserialize(&encoded_generator);
    assert!(r.is_ok());

    // The last byte only should have the sign bit. Set all other bits to
    // create a non-canonical encoding.
    encoded_generator[56] |= 0x7f;
    let r = <<Ed448Shake256 as Ciphersuite>::Group as Group>::deserialize(&encoded_generator);
    assert_eq!(r, Err(Error::MalformedElement));

    // Besides the last byte, it is still possible to get non-canonical encodings.
    // This is y = p + 19 which is non-canonical and maps to a valid prime-order point.
    let encoded_point = hex::decode("12000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00").unwrap().try_into().unwrap();
    let r = <<Ed448Shake256 as Ciphersuite>::Group as Group>::deserialize(&encoded_point);
    assert_eq!(r, Err(Error::MalformedElement));
}

#[test]
fn check_deserialize_non_prime_order() {
    let encoded_point =
        hex::decode("030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .try_into()
            .unwrap();
    let r = <<Ed448Shake256 as Ciphersuite>::Group as Group>::deserialize(&encoded_point);
    assert_eq!(r, Err(Error::InvalidNonPrimeOrderElement));
}
