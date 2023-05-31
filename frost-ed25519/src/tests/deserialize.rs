use crate::*;
use curve25519_dalek::{edwards::EdwardsPoint, traits::Identity};

#[test]
fn check_deserialize_non_prime_order() {
    let encoded_point =
        hex::decode("0300000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .try_into()
            .unwrap();
    let r = <Ed25519Sha512 as Ciphersuite>::Group::deserialize(&encoded_point);
    assert_eq!(r, Err(GroupError::InvalidNonPrimeOrderElement));
}

#[test]
fn check_deserialize_identity() {
    let encoded_identity = EdwardsPoint::identity().compress().to_bytes();

    let r = <Ed25519Sha512 as Ciphersuite>::Group::deserialize(&encoded_identity);
    assert_eq!(r, Err(GroupError::InvalidIdentityElement));
}
