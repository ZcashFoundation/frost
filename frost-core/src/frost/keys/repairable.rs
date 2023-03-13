//! Repairable Threshold Scheme

use std::collections::HashMap;

use crate::{frost::Identifier, Ciphersuite, CryptoRng, Field, Group, RngCore, Scalar};

use super::{generate_coefficients, SecretShare, SigningShare, VerifiableSecretSharingCommitment};

/// For every single helper i in helpers:

/// Generate random values for each helper for use in computing the value for the final helper
/// /// # i: the identifier of the signer helping
/// # helpers: as above
/// # share_i: i's secret share
/// # Output: i_deltas: random values that sum up to zeta_i * share _i

pub fn generate_random_values<C: Ciphersuite, R: RngCore + CryptoRng>(
    helpers: &[Identifier<C>],
    share_i: &SecretShare<C>,
    rng: &mut R,
    participant: Identifier<C>,
    current_helper: Identifier<C>,
) -> HashMap<Identifier<C>, Scalar<C>> {
    let rand_val: Vec<Scalar<C>> = generate_coefficients::<C, R>(helpers.len() - 1, rng);

    compute_random_values(helpers, share_i, &rand_val, participant, current_helper)
}

/// Temp <- don't make public - TODO
pub fn compute_lagrange_coefficient<C: Ciphersuite>(
    helpers: &[Identifier<C>],
    participant: Identifier<C>,
    current_helper: Identifier<C>,
) -> Scalar<C> {
    let mut num = <<C::Group as Group>::Field>::one();
    let mut den = <<C::Group as Group>::Field>::one();

    for j in helpers.iter().skip(0) {
        if current_helper == *j {
            continue;
        }

        num *= current_helper - participant;
        den *= *j - current_helper;
    }

    num * <<C::Group as Group>::Field>::invert(&den).unwrap()
}

fn compute_random_values<C: Ciphersuite>(
    helpers: &[Identifier<C>],
    share_i: &SecretShare<C>,
    random_values: &Vec<Scalar<C>>,
    participant: Identifier<C>,
    current_helper: Identifier<C>,
) -> HashMap<Identifier<C>, Scalar<C>> {
    // Calculate Lagrange Coefficient

    let zeta_i = compute_lagrange_coefficient(helpers, participant, current_helper);

    let lhs = zeta_i * share_i.value.0;

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

/// # Communication round:
/// # Helper i sends deltas_i[j] to helper j

/// # deltas_j: values received by j in the communication round
/// # Output: sigma_j

pub fn compute_sum_of_random_values<C: Ciphersuite>(deltas_j: &[Scalar<C>]) -> Scalar<C> {
    let mut sigma_j = <<C::Group as Group>::Field>::zero();

    for v in deltas_j {
        sigma_j = sigma_j + *v;
    }

    sigma_j
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
    let mut share = <<C::Group as Group>::Field>::zero();

    for v in sigmas {
        share = share + *v;
    }

    SecretShare {
        identifier,
        value: SigningShare(share),
        commitment: commitment.clone(),
    }
}
