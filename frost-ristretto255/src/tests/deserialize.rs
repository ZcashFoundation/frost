use crate::*;
use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use frost_core::{Ciphersuite, Group, GroupError};

#[test]
fn check_deserialize_identity() {
    let encoded_identity = RistrettoPoint::identity().compress().to_bytes();

    let r = <Ristretto255Sha512 as Ciphersuite>::Group::deserialize(&encoded_identity);
    assert_eq!(r, Err(GroupError::InvalidIdentityElement));
}
