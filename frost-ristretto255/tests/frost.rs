use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use frost_ristretto255::*;
use lazy_static::lazy_static;
use rand::thread_rng;
use serde_json::Value;

#[test]
fn check_sign_with_dealer() {
    let rng = thread_rng();

    frost_core::tests::check_sign_with_dealer::<Ristretto255Sha512, _>(rng);
}

#[test]
fn check_sign_with_dkg() {
    let rng = thread_rng();

    frost_core::tests::check_sign_with_dkg::<Ristretto255Sha512, _>(rng);
}

#[test]
fn check_batch_verify() {
    let rng = thread_rng();

    frost_core::tests::batch::batch_verify::<Ristretto255Sha512, _>(rng);
}

#[test]
fn check_bad_batch_verify() {
    let rng = thread_rng();

    frost_core::tests::batch::bad_batch_verify::<Ristretto255Sha512, _>(rng);
}

#[test]
fn check_deserialize_identity() {
    let encoded_identity = RistrettoPoint::identity().compress().to_bytes();

    let r = <Ristretto255Sha512 as Ciphersuite>::Group::deserialize(&encoded_identity);
    assert_eq!(r, Err(GroupError::InvalidIdentityElement));
}

lazy_static! {
    pub static ref REPAIR_SHARE: Value =
        serde_json::from_str(include_str!("repair-share.json").trim()).unwrap();
}

#[test]
fn check_repair_share_step_1() {
    let rng = thread_rng();

    frost_core::tests::repairable::check_repair_share_step_1::<Ristretto255Sha512, _>(rng);
}

#[test]
fn check_repair_share_step_2() {
    frost_core::tests::repairable::check_repair_share_step_2::<Ristretto255Sha512>(&REPAIR_SHARE);
}

#[test]
fn check_repair_share_step_3() {
    let rng = thread_rng();
    frost_core::tests::repairable::check_repair_share_step_3::<Ristretto255Sha512, _>(
        rng,
        &REPAIR_SHARE,
    );
}

#[test]
fn check_rts() {
    let rng = thread_rng();

    frost_core::tests::repairable::check_rts::<Ristretto255Sha512, _>(rng);
}
