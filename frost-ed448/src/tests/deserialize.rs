use crate::*;
use ed448_goldilocks::curve::ExtendedPoint;
use frost_core::Ciphersuite;

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
fn check_deserialize_identity() {
    let encoded_identity = ExtendedPoint::identity().compress().0;

    let r = <Ed448Shake256 as Ciphersuite>::Group::deserialize(&encoded_identity);
    assert_eq!(r, Err(GroupError::InvalidIdentityElement));
}
