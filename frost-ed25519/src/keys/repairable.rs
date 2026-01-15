//! Repairable Threshold Scheme
//!
//! Implements the Repairable Threshold Scheme (RTS) from <https://eprint.iacr.org/2017/1155>.
//! The RTS is used to help a signer (participant) repair their lost share. This is achieved
//! using a subset of the other signers know here as `helpers`.

use alloc::collections::BTreeMap;

use crate::keys::{KeyPackage, PublicKeyPackage};
// This is imported separately to make `gencode` work.
// (if it were below, the position of the import would vary between ciphersuites
//  after `cargo fmt`)
use crate::{frost, Ciphersuite, CryptoRng, Identifier, RngCore};
use crate::{Ed25519Sha512, Error};

/// A delta value which is the output of step 1 of RTS.
pub type Delta = frost::keys::repairable::Delta<Ed25519Sha512>;

/// A sigma value which is the output of step 2 of RTS.
pub type Sigma = frost::keys::repairable::Sigma<Ed25519Sha512>;

/// Step 1 of RTS.
///
/// Generates the "delta" values from the helper with `key_package_i` to send to
/// `helpers` (which includes the helper with `key_package_i`), to help
/// `participant` recover their share.
///
/// Returns a BTreeMap mapping which value should be sent to which participant.
pub fn repair_share_step_1<C: Ciphersuite, R: RngCore + CryptoRng>(
    helpers: &[Identifier],
    key_package_i: &KeyPackage,
    rng: &mut R,
    participant: Identifier,
) -> Result<BTreeMap<Identifier, Delta>, Error> {
    frost::keys::repairable::repair_share_step_1(helpers, key_package_i, rng, participant)
}

/// Step 2 of RTS.
///
/// Generates the "sigma" value from all `deltas` received from all helpers.
/// The "sigma" value must be sent to the participant repairing their share.
pub fn repair_share_step_2(deltas: &[Delta]) -> Sigma {
    frost::keys::repairable::repair_share_step_2::<Ed25519Sha512>(deltas)
}

/// Step 3 of RTS.
///
/// The participant with the given `identifier` recovers their `KeyPackage`
/// with the "sigma" values received from all helpers and the `PublicKeyPackage`
/// of the group (which can be sent by any of the helpers).
///
/// Returns an error if the `min_signers` field is not set in the `PublicKeyPackage`.
/// This happens for `PublicKeyPackage`s created before the 3.0.0 release;
/// in that case, the user should set the `min_signers` field manually.
pub fn repair_share_step_3(
    sigmas: &[Sigma],
    identifier: Identifier,
    public_key_package: &PublicKeyPackage,
) -> Result<KeyPackage, Error> {
    frost::keys::repairable::repair_share_step_3(sigmas, identifier, public_key_package)
}

#[cfg(test)]
mod tests {

    use lazy_static::lazy_static;

    use serde_json::Value;

    use crate::Ed25519Sha512;

    lazy_static! {
        pub static ref REPAIR_SHARE: Value =
            serde_json::from_str(include_str!("../../tests/helpers/repair-share.json").trim())
                .unwrap();
    }

    #[test]
    fn check_repair_share_step_1() {
        let rng = rand::rngs::OsRng;

        frost_core::tests::repairable::check_repair_share_step_1::<Ed25519Sha512, _>(rng);
    }

    #[test]
    fn check_repair_share_step_2() {
        frost_core::tests::repairable::check_repair_share_step_2::<Ed25519Sha512>(&REPAIR_SHARE);
    }

    #[test]
    fn check_repair_share_step_3() {
        let rng = rand::rngs::OsRng;
        frost_core::tests::repairable::check_repair_share_step_3::<Ed25519Sha512, _>(
            rng,
            &REPAIR_SHARE,
        );
    }

    #[test]
    fn check_repair_share_step_1_fails_with_invalid_min_signers() {
        let rng = rand::rngs::OsRng;
        frost_core::tests::repairable::check_repair_share_step_1_fails_with_invalid_min_signers::<
            Ed25519Sha512,
            _,
        >(rng);
    }
}
