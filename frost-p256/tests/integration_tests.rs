use frost_p256::*;
use lazy_static::lazy_static;
use rand::thread_rng;
use serde_json::Value;

#[test]
fn check_zero_key_fails() {
    frost_core::tests::ciphersuite_generic::check_zero_key_fails::<P256Sha256>();
}

#[test]
fn check_sign_with_dkg() {
    let rng = thread_rng();

    frost_core::tests::ciphersuite_generic::check_sign_with_dkg::<P256Sha256, _>(rng);
}

#[test]
fn check_dkg_part1_fails_with_invalid_signers_min_signers() {
    let rng = thread_rng();

    let min_signers = 1;
    let max_signers = 3;
    let error = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        P256Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_dkg_part1_fails_with_min_signers_greater_than_max() {
    let rng = thread_rng();

    let min_signers = 3;
    let max_signers = 2;
    let error: frost_core::Error<P256Sha256> = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        P256Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_dkg_part1_fails_with_invalid_signers_max_signers() {
    let rng = thread_rng();

    let min_signers = 3;
    let max_signers = 1;
    let error = Error::InvalidMaxSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        P256Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_rts() {
    let rng = thread_rng();

    frost_core::tests::repairable::check_rts::<P256Sha256, _>(rng);
}

#[test]
fn check_refresh_shares_with_dealer() {
    let rng = thread_rng();

    frost_core::tests::refresh::check_refresh_shares_with_dealer::<P256Sha256, _>(rng);
}

#[test]
fn check_refresh_shares_with_dealer_serialisation() {
    let rng = thread_rng();

    frost_core::tests::refresh::check_refresh_shares_with_dealer_serialisation::<P256Sha256, _>(
        rng,
    );
}

#[test]
fn check_refresh_shares_with_dealer_fails_with_invalid_public_key_package() {
    let rng = thread_rng();

    frost_core::tests::refresh::check_refresh_shares_with_dealer_fails_with_invalid_public_key_package::<
        P256Sha256,
        _,
    >(rng);
}

#[test]
fn check_refresh_shares_with_dealer_fails_with_invalid_min_signers() {
    let rng = thread_rng();
    let identifiers = vec![
        Identifier::try_from(1).unwrap(),
        Identifier::try_from(3).unwrap(),
        Identifier::try_from(4).unwrap(),
        Identifier::try_from(5).unwrap(),
    ];
    let min_signers = 1;
    let max_signers = 4;
    let error = Error::InvalidMinSigners;

    frost_core::tests::refresh::check_refresh_shares_with_dealer_fails_with_invalid_signers::<
        P256Sha256,
        _,
    >(max_signers, min_signers, &identifiers, error, rng);
}

#[test]
fn check_refresh_shares_with_dealer_fails_with_unequal_num_identifiers_and_max_signers() {
    let rng = thread_rng();
    let identifiers = vec![
        Identifier::try_from(1).unwrap(),
        Identifier::try_from(3).unwrap(),
        Identifier::try_from(4).unwrap(),
        Identifier::try_from(5).unwrap(),
    ];
    let min_signers = 3;
    let max_signers = 3;
    let error: frost_core::Error<P256Sha256> = Error::IncorrectNumberOfIdentifiers;

    frost_core::tests::refresh::check_refresh_shares_with_dealer_fails_with_invalid_signers::<
        P256Sha256,
        _,
    >(max_signers, min_signers, &identifiers, error, rng);
}

#[test]
fn check_refresh_shares_with_dealer_fails_with_min_signers_greater_than_max() {
    let rng = thread_rng();
    let identifiers = vec![
        Identifier::try_from(1).unwrap(),
        Identifier::try_from(3).unwrap(),
        Identifier::try_from(4).unwrap(),
        Identifier::try_from(5).unwrap(),
    ];
    let min_signers = 6;
    let max_signers = 4;
    let error: frost_core::Error<P256Sha256> = Error::InvalidMinSigners;

    frost_core::tests::refresh::check_refresh_shares_with_dealer_fails_with_invalid_signers::<
        P256Sha256,
        _,
    >(max_signers, min_signers, &identifiers, error, rng);
}

#[test]
fn check_refresh_shares_with_dealer_fails_with_invalid_max_signers() {
    let rng = thread_rng();
    let identifiers = vec![Identifier::try_from(1).unwrap()];
    let min_signers = 3;
    let max_signers = 1;
    let error = Error::InvalidMaxSigners;

    frost_core::tests::refresh::check_refresh_shares_with_dealer_fails_with_invalid_signers::<
        P256Sha256,
        _,
    >(max_signers, min_signers, &identifiers, error, rng);
}

#[test]
fn check_refresh_shares_with_dealer_fails_with_invalid_identifier() {
    let rng = thread_rng();
    let identifiers = vec![
        Identifier::try_from(8).unwrap(),
        Identifier::try_from(3).unwrap(),
        Identifier::try_from(4).unwrap(),
        Identifier::try_from(6).unwrap(),
    ];
    let min_signers = 2;
    let max_signers = 4;
    let error = Error::UnknownIdentifier;

    frost_core::tests::refresh::check_refresh_shares_with_dealer_fails_with_invalid_signers::<
        P256Sha256,
        _,
    >(max_signers, min_signers, &identifiers, error, rng);
}

#[test]
fn check_refresh_shares_with_dkg() {
    let rng = thread_rng();

    frost_core::tests::refresh::check_refresh_shares_with_dkg::<P256Sha256, _>(rng);
}

#[test]
fn check_sign_with_dealer() {
    let rng = thread_rng();

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<P256Sha256, _>(rng);
}

#[test]
fn check_sign_with_dealer_fails_with_invalid_min_signers() {
    let rng = thread_rng();

    let min_signers = 1;
    let max_signers = 3;
    let error = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        P256Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_sign_with_dealer_fails_with_min_signers_greater_than_max() {
    let rng = thread_rng();

    let min_signers = 3;
    let max_signers = 2;
    let error: frost_core::Error<P256Sha256> = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        P256Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_sign_with_dealer_fails_with_invalid_max_signers() {
    let rng = thread_rng();

    let min_signers = 3;
    let max_signers = 1;
    let error = Error::InvalidMaxSigners;

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        P256Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

/// This is testing that Shamir's secret sharing to compute and arbitrary
/// value is working.
#[test]
fn check_share_generation_p256_sha256() {
    let rng = thread_rng();
    frost_core::tests::ciphersuite_generic::check_share_generation::<P256Sha256, _>(rng);
}

#[test]
fn check_share_generation_fails_with_invalid_min_signers() {
    let rng = thread_rng();

    let min_signers = 0;
    let max_signers = 3;
    let error = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_share_generation_fails_with_invalid_signers::<
        P256Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_share_generation_fails_with_min_signers_greater_than_max() {
    let rng = thread_rng();

    let min_signers = 3;
    let max_signers = 2;
    let error: frost_core::Error<P256Sha256> = Error::InvalidMinSigners;

    frost_core::tests::ciphersuite_generic::check_share_generation_fails_with_invalid_signers::<
        P256Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_share_generation_fails_with_invalid_max_signers() {
    let rng = thread_rng();

    let min_signers = 3;
    let max_signers = 0;
    let error = Error::InvalidMaxSigners;

    frost_core::tests::ciphersuite_generic::check_share_generation_fails_with_invalid_signers::<
        P256Sha256,
        _,
    >(min_signers, max_signers, error, rng);
}

lazy_static! {
    pub static ref VECTORS: Value =
        serde_json::from_str(include_str!("../tests/helpers/vectors.json").trim())
            .expect("Test vector is valid JSON");
    pub static ref VECTORS_BIG_IDENTIFIER: Value =
        serde_json::from_str(include_str!("../tests/helpers/vectors-big-identifier.json").trim())
            .expect("Test vector is valid JSON");
    pub static ref VECTORS_DKG: Value =
        serde_json::from_str(include_str!("../tests/helpers/vectors_dkg.json").trim())
            .expect("Test vector is valid JSON");
}

#[test]
fn check_sign_with_test_vectors() {
    frost_core::tests::vectors::check_sign_with_test_vectors::<P256Sha256>(&VECTORS);
}

#[test]
fn check_sign_with_test_vectors_dkg() {
    frost_core::tests::vectors_dkg::check_dkg_keygen::<P256Sha256>(&VECTORS_DKG);
}

#[test]
fn check_sign_with_test_vectors_with_big_identifiers() {
    frost_core::tests::vectors::check_sign_with_test_vectors::<P256Sha256>(&VECTORS_BIG_IDENTIFIER);
}

#[test]
fn check_error_culprit() {
    frost_core::tests::ciphersuite_generic::check_error_culprit::<P256Sha256>();
}

#[test]
fn check_identifier_derivation() {
    frost_core::tests::ciphersuite_generic::check_identifier_derivation::<P256Sha256>();
}

// Explicit test which is used in a documentation snippet
#[test]
#[allow(unused_variables)]
fn check_identifier_generation() -> Result<(), Error> {
    // ANCHOR: dkg_identifier
    let participant_identifier = Identifier::try_from(7u16)?;
    let participant_identifier = Identifier::derive("alice@example.com".as_bytes())?;
    // ANCHOR_END: dkg_identifier
    Ok(())
}

#[test]
fn check_sign_with_dealer_and_identifiers() {
    let rng = thread_rng();

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_and_identifiers::<P256Sha256, _>(
        rng,
    );
}

#[test]
fn check_sign_with_missing_identifier() {
    let rng = thread_rng();
    frost_core::tests::ciphersuite_generic::check_sign_with_missing_identifier::<P256Sha256, _>(
        rng,
    );
}

#[test]
fn check_sign_with_incorrect_commitments() {
    let rng = thread_rng();
    frost_core::tests::ciphersuite_generic::check_sign_with_incorrect_commitments::<P256Sha256, _>(
        rng,
    );
}
