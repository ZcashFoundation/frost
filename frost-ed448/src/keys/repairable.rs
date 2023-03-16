/// Repairable Threshold Scheme

#![doc = include_str!("../../repairable.md")]

use std::collections::HashMap;

use crate::{frost::Identifier, Ciphersuite, CryptoRng, Field, Group, RngCore, Scalar};

use super::{SecretShare};

/// Generate random values for each helper - 1 for use in computing the value for the final helper

pub fn repair_share_step_1<R: RngCore + CryptoRng>(
    helpers: &[Identifier<C>],
    share_i: &SecretShare<C>,
    zeta_i: Scalar<C>,
    rng: &mut R,
) -> HashMap<Identifier<C>, Scalar<C>> {
    frost::keys::repairable::repair_share_step_1(identifier, max_signers, min_signers, &mut rng)
}

/// # Communication round:
/// # Helper i sends deltas_i[j] to helper j

/// # deltas_j: values received by j in the communication round
/// # Output: sigma_j

pub fn repair_share_step_3<C: Ciphersuite>(deltas_j: &[Scalar<C>]) -> Scalar<C> {
    frost::keys::repairable::repair_share_step_3(deltas_j)
}

/// # Communication round
/// # Helper j sends sigma_j to signer r

/// # sigmas: all sigma_j received from each helper j
/// # Output: share_r: r's secret share

pub fn repair_share_step_5<C: Ciphersuite>(
    sigmas: &[Scalar<C>],
    identifier: Identifier<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> SecretShare<C> {
    frost::keys::repairable::repair_share(sigmas, identifier, commitment)
}
