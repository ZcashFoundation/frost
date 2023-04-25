/// Repairable Threshold Schemes
#![doc = include_str!("../../repairable.md")]

use std::collections::HashMap;

use crate::{frost::Identifier, Ciphersuite, CryptoRng, Field, Group, RngCore, Scalar};

use super::SecretShare;

/// Step 1 of RTS.
///
/// Generates the "delta" values from `helper_i` to help `participant` recover their share
/// where `helpers` contains the identifiers of all the helpers (including `helper_i`), and `share_i`
/// is the share of `helper_i`.
///
/// Returns a HashMap mapping which value should be sent to which participant.
pub fn repair_share_step_1<R: RngCore + CryptoRng>(
    helpers: &[Identifier<C>],
    share_i: &SecretShare<C>,
    zeta_i: Scalar<C>,
    rng: &mut R,
) -> HashMap<Identifier<C>, Scalar<C>> {
    frost::keys::repairable::repair_share_step_1(identifier, max_signers, min_signers, &mut rng)
}

/// Step 3 of RTS.
///
/// Generates the `sigma` values from all `deltas` received from `helpers`
/// to help `participant` recover their share.
/// `sigma` is the sum of all received `delta` and the `delta_i` generated for `helper_i`.
///
/// Returns a scalar
pub fn repair_share_step_2<C: Ciphersuite>(deltas_j: &[Scalar<C>]) -> Scalar<C> {
    frost::keys::repairable::repair_share_step_2(deltas_j)
}

/// Step 5 of RTS
///
/// The `participant` sums all `sigma_j` received to compute the `share`. The `SecretShare`
/// is made up of the `identifier`and `commitment` of the `participant` as well as the
/// `value` which is the `SigningShare`.
pub fn repair_share_step_3<C: Ciphersuite>(
    sigmas: &[Scalar<C>],
    identifier: Identifier<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> SecretShare<C> {
    frost::keys::repairable::repair_share(sigmas, identifier, commitment)
}
