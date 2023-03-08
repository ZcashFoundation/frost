/// Repairable Threshold Scheme

#![doc = include_str!("../../repairable.md")]

use std::collections::HashMap;

use crate::{frost::Identifier, Ciphersuite, CryptoRng, Field, Group, RngCore, Scalar};

use super::{SecretShare};

/// Generate random values for each helper - 1 for use in computing the value for the final helper

pub fn generate_random_values<R: RngCore + CryptoRng>(
    helpers: &[Identifier<C>],
    share_i: &SecretShare<C>,
    zeta_i: Scalar<C>,
    rng: &mut R,
) -> HashMap<Identifier<C>, Scalar<C>> {
    frost::keys::repairable::generate_random_values(identifier, max_signers, min_signers, &mut rng)
}

/// # Communication round:
/// # Helper i sends deltas_i[j] to helper j

/// # deltas_j: values received by j in the communication round
/// # Output: sigma_j

pub fn compute_sum_of_random_values<C: Ciphersuite>(deltas_j: &[Scalar<C>]) -> Scalar<C> {
    frost::keys::repairable::compute_sum_of_random_values(deltas_j)
}

/// # Communication round
/// # Helper j sends sigma_j to signer r

/// # sigmas: all sigma_j received from each helper j
/// # Output: share_r: r's secret share

pub fn recover_share<C: Ciphersuite>(
    sigmas: &[Scalar<C>],
    identifier: Identifier<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> SecretShare<C> {
    frost::keys::repairable::recover_share(sigmas, identifier, commitment)
}
