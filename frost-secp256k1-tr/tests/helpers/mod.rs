// Required since each integration test is compiled as a separated crate,
// and each one uses only part of the module.
#![allow(dead_code)]

use frost_secp256k1_tr::Secp256K1Sha256TR;
use secp256k1::Secp256k1;

pub mod samples;

pub fn verify_signature(
    msg: &[u8],
    group_signature: &frost_core::Signature<Secp256K1Sha256TR>,
    group_pubkey: &frost_core::VerifyingKey<Secp256K1Sha256TR>,
) {
    let secp = Secp256k1::new();
    let sig = secp256k1::schnorr::Signature::from_byte_array(
        group_signature.serialize().unwrap().try_into().unwrap(),
    );
    let pubkey = secp256k1::XOnlyPublicKey::from_byte_array(
        &group_pubkey.serialize().unwrap()[1..33].try_into().unwrap(),
    )
    .unwrap();
    secp.verify_schnorr(&sig, msg, &pubkey).unwrap();
}
