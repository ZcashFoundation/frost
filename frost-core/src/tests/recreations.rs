//! Test for recreating packages from their components, which shows that they
//! can be serialized and deserialized as the user wishes.

use crate::{
    frost::{
        keys::{
            dkg::{round1, round2},
            KeyPackage, PublicKeyPackage, SecretShare,
        },
        round1::SigningCommitments,
        round2::SignatureShare,
        SigningPackage,
    },
    Ciphersuite,
};

use super::samples;

/// Check if SigningCommitments can be recreated.
pub fn check_signing_commitments_recreation<C: Ciphersuite>() {
    let commitments = samples::signing_commitments::<C>();
    let identifier = commitments.identifier();
    let hiding = commitments.hiding();
    let binding = commitments.binding();
    let new_commitments = SigningCommitments::<C>::new(*identifier, *hiding, *binding);
    assert!(commitments == new_commitments);
}

/// Check if SigningPackage can be recreated.
pub fn check_signing_package_recreation<C: Ciphersuite>() {
    let signing_package = samples::signing_package::<C>();

    let commitments = signing_package
        .signing_commitments()
        .values()
        .cloned()
        .collect();
    let message = signing_package.message();

    let new_signing_package = SigningPackage::new(commitments, message);
    assert!(signing_package == new_signing_package);
}

/// Check if SignatureShare can be recreated.
pub fn check_signature_share_recreation<C: Ciphersuite>() {
    let signature_share = samples::signature_share::<C>();

    let identifier = signature_share.identifier();
    let signature_response = signature_share.signature();

    let new_signature_share = SignatureShare::new(*identifier, *signature_response);
    assert!(signature_share == new_signature_share);
}

/// Check if SecretShare can be recreated.
pub fn check_secret_share_recreation<C: Ciphersuite>() {
    let secret_share = samples::secret_share::<C>();

    let identifier = secret_share.identifier();
    let value = secret_share.value();
    let commitment = secret_share.commitment();

    let new_secret_share = SecretShare::new(*identifier, *value, commitment.clone());

    assert!(secret_share == new_secret_share);
}

/// Check if KeyPackage can be recreated.
pub fn check_key_package_recreation<C: Ciphersuite>() {
    let key_package = samples::key_package::<C>();

    let identifier = key_package.identifier();
    let signing_share = key_package.secret_share();
    let verifying_share = key_package.public();
    let verifying_key = key_package.group_public();

    let new_key_package = KeyPackage::new(
        *identifier,
        *signing_share,
        *verifying_share,
        *verifying_key,
    );

    assert!(key_package == new_key_package);
}

/// Check if PublicKeyPackage can be recreated.
pub fn check_public_key_package_recreation<C: Ciphersuite>() {
    let public_key_package = samples::public_key_package::<C>();

    let signer_pubkeys = public_key_package.signer_pubkeys();
    let verifying_key = public_key_package.group_public();

    let new_public_key_package = PublicKeyPackage::new(signer_pubkeys.clone(), *verifying_key);

    assert!(public_key_package == new_public_key_package);
}

/// Check if round1::Package can be recreated.
pub fn check_round1_package_recreation<C: Ciphersuite>() {
    let round1_package = samples::round1_package::<C>();

    let identifier = round1_package.sender_identifier();
    let vss_commitment = round1_package.commitment();
    let signature = round1_package.proof_of_knowledge();

    let new_round1_package = round1::Package::new(*identifier, vss_commitment.clone(), *signature);

    assert!(round1_package == new_round1_package);
}

/// Check if round2::Package can be recreated.
pub fn check_round2_package_recreation<C: Ciphersuite>() {
    let round2_package = samples::round2_package::<C>();

    let sender_identifier = round2_package.sender_identifier();
    let receiver_identifier = round2_package.receiver_identifier();
    let signing_share = round2_package.secret_share();

    let new_round2_package =
        round2::Package::new(*sender_identifier, *receiver_identifier, *signing_share);

    assert!(round2_package == new_round2_package);
}
