//! Test for recreating packages from their components, which shows that they
//! can be serialized and deserialized as the user wishes.

use frost_ed25519::{
    keys::{
        dkg::{round1, round2},
        KeyPackage, PublicKeyPackage, SecretShare,
    },
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    SigningPackage,
};

mod helpers;

use helpers::samples;

/// Check if SigningNonces can be recreated.
#[test]
fn check_signing_nonces_recreation() {
    let nonces = samples::signing_nonces();
    let hiding = nonces.hiding();
    let binding = nonces.binding();
    let new_nonces = SigningNonces::from_nonces(*hiding, *binding);
    assert!(nonces == new_nonces);
}

/// Check if SigningCommitments can be recreated.
#[test]
fn check_signing_commitments_recreation() {
    let commitments = samples::signing_commitments();
    let hiding = commitments.hiding();
    let binding = commitments.binding();
    let new_commitments = SigningCommitments::new(*hiding, *binding);
    assert!(commitments == new_commitments);
}

/// Check if SigningPackage can be recreated.
#[test]
fn check_signing_package_recreation() {
    let signing_package = samples::signing_package();

    let commitments = signing_package.signing_commitments();
    let message = signing_package.message();

    let new_signing_package = SigningPackage::new(commitments.clone(), message);
    assert!(signing_package == new_signing_package);
}

/// Check if SignatureShare can be recreated.
#[test]
fn check_signature_share_recreation() {
    let signature_share = samples::signature_share();

    let encoded = signature_share.serialize();

    let new_signature_share = SignatureShare::deserialize(&encoded).unwrap();
    assert!(signature_share == new_signature_share);
}

/// Check if SecretShare can be recreated.
#[test]
fn check_secret_share_recreation() {
    let secret_share = samples::secret_share();

    let identifier = secret_share.identifier();
    let value = secret_share.signing_share();
    let commitment = secret_share.commitment();

    let new_secret_share = SecretShare::new(*identifier, *value, commitment.clone());

    assert!(secret_share == new_secret_share);
}

/// Check if KeyPackage can be recreated.
#[test]
fn check_key_package_recreation() {
    let key_package = samples::key_package();

    let identifier = key_package.identifier();
    let signing_share = key_package.signing_share();
    let verifying_share = key_package.verifying_share();
    let verifying_key = key_package.verifying_key();
    let min_signers = key_package.min_signers();

    let new_key_package = KeyPackage::new(
        *identifier,
        *signing_share,
        *verifying_share,
        *verifying_key,
        *min_signers,
    );

    assert!(key_package == new_key_package);
}

/// Check if PublicKeyPackage can be recreated.
#[test]
fn check_public_key_package_recreation() {
    let public_key_package = samples::public_key_package();

    let verifying_shares = public_key_package.verifying_shares();
    let verifying_key = public_key_package.verifying_key();

    let new_public_key_package = PublicKeyPackage::new(verifying_shares.clone(), *verifying_key);

    assert!(public_key_package == new_public_key_package);
}

/// Check if round1::Package can be recreated.
#[test]
fn check_round1_package_recreation() {
    let round1_package = samples::round1_package();

    let vss_commitment = round1_package.commitment();
    let signature = round1_package.proof_of_knowledge();

    let new_round1_package = round1::Package::new(vss_commitment.clone(), *signature);

    assert!(round1_package == new_round1_package);
}

/// Check if round2::Package can be recreated.
#[test]
fn check_round2_package_recreation() {
    let round2_package = samples::round2_package();

    let signing_share = round2_package.signing_share();

    let new_round2_package = round2::Package::new(*signing_share);

    assert!(round2_package == new_round2_package);
}
