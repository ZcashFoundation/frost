//! Repairable Threshold Scheme

use std::collections::HashMap;

use crate::{frost::Identifier, Ciphersuite, CryptoRng, Field, Group, RngCore, Scalar};

use super::{generate_coefficients, SecretShare};

/// # For every single helper i in helpers:

/// Generate random values for each helper - 1 for use in computing the value for the final helper

pub fn generate_random_values<C: Ciphersuite, R: RngCore + CryptoRng>(
    helpers: &[Identifier<C>],
    share_i: &SecretShare<C>,
    zeta_i: Scalar<C>,
    rng: &mut R,
) -> HashMap<Identifier<C>, Scalar<C>> {
    let rand_val: Vec<Scalar<C>> = generate_coefficients::<C, R>(helpers.len() - 2, rng);

    compute_random_values(helpers, share_i, zeta_i, &rand_val)
}

/// # i: the identifier of the signer helping
/// # helpers: as above

/// # share_i: i's secret share
/// # zeta_i: Lagrange coefficient
/// # Output: i_deltas: random values that sum up to zeta_i * share _i

pub fn compute_random_values<C: Ciphersuite>(
    helpers: &[Identifier<C>],
    share_i: &SecretShare<C>,
    zeta_i: Scalar<C>,
    random_values: &Vec<Scalar<C>>,
) -> HashMap<Identifier<C>, Scalar<C>> {
    let lhs = zeta_i * share_i.value.0; // Here

    let mut out: HashMap<Identifier<C>, Scalar<C>> = helpers
        .iter()
        .copied()
        .zip(random_values.iter().copied())
        .collect();

    let mut sum_rand_val = <<C::Group as Group>::Field>::zero();

    for v in random_values {
        sum_rand_val = sum_rand_val + *v;
    }

    out.insert(helpers[helpers.len() - 1], lhs - sum_rand_val);

    out
}

// # Communication round:
// # Helper i sends deltas_i[j] to helper j

// # deltas_j: values received by j in the communication round
// # Output: sigma_j

// pub fn compute_sum_of_random_values<C: Ciphersuite>(deltas_j: &[Scalar<C>]) -> Scalar<C> {

// }

// # Communication round
// # Helper j sends sigma_j to signer r

// # sigmas: all sigma_j received from each helper j
// # Output: share_r: r's secret share

// pub fn recover_share<C: Ciphersuite>(
//     sigmas: &[Scalar<C>],
//     identifier: Identifier<C>,
//     commitment: VerifiableSecretSharingCommitment<C>,
// ) -> SecretShare<C> {
// }
