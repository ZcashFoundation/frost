//! Repairable Threshold Scheme
//!

// # For every single helper i in helpers:

use crate::{frost::Identifier, Ciphersuite, Scalar};

use super::SecretShare;

/// # i: the identifier of the signer helping
/// # helpers: as above
/// # share_i: i's secret share
/// # zeta_i: Lagrange coefficient (?)
/// # - Note: may be able to be computed inside the function, check
/// # Output: i_deltas: random values that sum up to zeta_i * share _i
pub fn compute_random_values<C: Ciphersuite>(
    helpers: &[Identifier<C>],
    share_i: &SecretShare<C>,
    zeta_i: Scalar<C>,
) -> Vec<Scalar<C>> {
    vec![]
}

// # Communication round:
// # Helper i sends deltas_i[j] to helper j

// # j: the identifier of the signer helping
// # helpers: as above
// # deltas_j: values received by j in the communication round
// # Output: sigma_j
// pub fn compute_sum_of_random_values(j, helpers, deltas_j) -> sigma_j

// # Communication round
// # Helper j sends sigma_j to signer r

// # sigmas: all sigma_j received from each helper j
// # Output: share_r: r's secret share
// pub fn recover_share(sigmas) -> share_r
