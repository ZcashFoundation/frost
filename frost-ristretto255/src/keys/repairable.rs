//! Repairable Threshold Scheme
//!
//! Implements the Repairable Threshold Scheme (RTS) from <https://eprint.iacr.org/2017/1155>.
//! The RTS is used to help a signer (participant) repair their lost share. This is achieved
//! using a subset of the other signers know here as `helpers`.

use std::collections::HashMap;

// This is imported separately to make `gencode` work.
// (if it were below, the position of the import would vary between ciphersuites
//  after `cargo fmt`)
use crate::Ristretto255Sha512;
use crate::{frost, Ciphersuite, CryptoRng, Identifier, RngCore, Scalar};

use super::{SecretShare, VerifiableSecretSharingCommitment};

/// Step 1 of RTS.
///
/// Generates the "delta" values from `helper_i` to help `participant` recover their share
/// where `helpers` contains the identifiers of all the helpers (including `helper_i`), and `share_i`
/// is the share of `helper_i`.
///
/// Returns a HashMap mapping which value should be sent to which participant.
pub fn repair_share_step_1<C: Ciphersuite, R: RngCore + CryptoRng>(
    helpers: &[Identifier],
    share_i: &SecretShare,
    rng: &mut R,
    participant: Identifier,
) -> HashMap<Identifier, Scalar> {
    frost::keys::repairable::repair_share_step_1(helpers, share_i, rng, participant)
}

/// Step 2 of RTS.
///
/// Generates the `sigma` values from all `deltas` received from `helpers`
/// to help `participant` recover their share.
/// `sigma` is the sum of all received `delta` and the `delta_i` generated for `helper_i`.
///
/// Returns a scalar
pub fn repair_share_step_2(deltas_j: &[Scalar]) -> Scalar {
    frost::keys::repairable::repair_share_step_2::<Ristretto255Sha512>(deltas_j)
}

/// Step 3 of RTS
///
/// The `participant` sums all `sigma_j` received to compute the `share`. The `SecretShare`
/// is made up of the `identifier`and `commitment` of the `participant` as well as the
/// `value` which is the `SigningShare`.
pub fn repair_share_step_3(
    sigmas: &[Scalar],
    identifier: Identifier,
    commitment: &VerifiableSecretSharingCommitment,
) -> SecretShare {
    frost::keys::repairable::repair_share_step_3(sigmas, identifier, commitment)
}
