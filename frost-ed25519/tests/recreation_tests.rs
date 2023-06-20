use frost_core::tests::recreations;

type C = frost_ed25519::Ed25519Sha512;

#[test]
fn check_signing_commitments_recreation() {
    recreations::check_signing_commitments_recreation::<C>();
}

#[test]
fn check_signing_package_recreation() {
    recreations::check_signing_package_recreation::<C>();
}

#[test]
fn check_signature_share_recreation() {
    recreations::check_signature_share_recreation::<C>();
}

#[test]
fn check_secret_share_recreation() {
    recreations::check_secret_share_recreation::<C>();
}

#[test]
fn check_key_package_recreation() {
    recreations::check_key_package_recreation::<C>();
}

#[test]
fn check_public_key_package_recreation() {
    recreations::check_public_key_package_recreation::<C>();
}

#[test]
fn check_round1_package_recreation() {
    recreations::check_round1_package_recreation::<C>();
}

#[test]
fn check_round2_package_recreation() {
    recreations::check_round2_package_recreation::<C>();
}
