use frost_secp256k1_tr::*;
use rand::thread_rng;

#[test]
fn check_tweaked_signing_key() {
    let signing_key = SigningKey::deserialize([0xAA; 32]).unwrap();
    let untweaked_verifying_key = VerifyingKey::from(signing_key);

    let mut rng = rand::thread_rng();
    let message = b"message";

    let untweaked_signature = signing_key.sign(&mut rng, &message);

    untweaked_verifying_key
        .verify(&message, &untweaked_signature)
        .expect("untweaked signature should be valid under untweaked verifying key");

    let signing_target = SigningTarget::new(
        &message,
        SigningParameters {
            tapscript_merkle_root: Some(vec![]),
        },
    );

    let tweaked_signature = signing_key.sign(&mut rng, signing_target.clone());

    untweaked_verifying_key
        .verify(&message, &tweaked_signature)
        .expect_err("tweaked signature should not be valid under untweaked verifying key");

    let tweaked_verifying_key = untweaked_verifying_key.effective_key(signing_target.sig_params());
    tweaked_verifying_key
        .verify(&message, &tweaked_signature)
        .expect("tweaked signature should be valid under tweaked verifying key");

    untweaked_verifying_key
        .verify(signing_target.clone(), &tweaked_signature)
        .expect(
            "tweaked signature should be valid under untweaked verifying key\
             when signing params are provided",
        );
}

#[test]
fn check_tweaked_sign_with_dkg() {
    let rng = thread_rng();

    frost_core::tests::ciphersuite_generic::check_sign_with_dkg::<Secp256K1Sha256, _>(
        rng,
        SigningTarget::new(
            b"message",
            SigningParameters {
                tapscript_merkle_root: Some(vec![]),
            },
        ),
    );
}
#[test]
fn check_tweaked_sign_with_dealer() {
    let rng = thread_rng();

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<Secp256K1Sha256, _>(
        rng,
        SigningTarget::new(
            b"message",
            SigningParameters {
                tapscript_merkle_root: Some(vec![]),
            },
        ),
    );
}

#[test]
fn check_tweaked_sign_with_dealer_and_identifiers() {
    let rng = thread_rng();

    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_and_identifiers::<
        Secp256K1Sha256,
        _,
    >(
        rng,
        SigningTarget::new(
            b"message",
            SigningParameters {
                tapscript_merkle_root: Some(vec![]),
            },
        ),
    );
}
