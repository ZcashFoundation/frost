//! Repairable Threshold Scheme

use std::collections::HashMap;

use crate::{frost::Identifier, Ciphersuite, CryptoRng, Field, Group, RngCore, Scalar};

use super::{generate_coefficients, SecretShare, SigningShare, VerifiableSecretSharingCommitment};

/// Step 1 of RTS. Generates the "delta" values from `helper_i` to help `participant` recover their share;
/// where `helpers` contains the identifiers of all the helpers (including `helper_i`), and `share_i`
/// is the share of `helper_i`.
/// 
/// Returns a HashMap mapping which value should be sent to which participant.
pub fn generate_deltas_to_repair_share<C: Ciphersuite, R: RngCore + CryptoRng>(
    helpers: &[Identifier<C>],
    share_i: &SecretShare<C>,
    rng: &mut R,
    participant: Identifier<C>,
    helper_i: Identifier<C>,
) -> HashMap<Identifier<C>, Scalar<C>> {
    let rand_val: Vec<Scalar<C>> = generate_coefficients::<C, R>(helpers.len() - 1, rng);

    compute_last_delta(helpers, share_i, &rand_val, participant, helper_i)
}

/// Compute the last delta value given the (generated uniformly at random) remaining ones
/// since they all must add up to `zeta_i * share_i`.
///
/// Returns a HashMap mapping which value should be sent to which participant.
fn compute_last_delta<C: Ciphersuite>(
    helpers: &[Identifier<C>],
    share_i: &SecretShare<C>,
    random_values: &Vec<Scalar<C>>,
    participant: Identifier<C>,
    helper_i: Identifier<C>,
) -> HashMap<Identifier<C>, Scalar<C>> {
    // Calculate Lagrange Coefficient for helper i
    let zeta_i = compute_lagrange_coefficient(helpers, participant, helper_i);

    let lhs = zeta_i * share_i.value.0;

    let mut out: HashMap<Identifier<C>, Scalar<C>> = helpers
        .iter()
        .copied()
        .zip(random_values.iter().copied())
        .collect();

    let mut sum_i_deltas = <<C::Group as Group>::Field>::zero();

    for v in random_values {
        sum_i_deltas = sum_i_deltas + *v;
    }

    out.insert(helpers[helpers.len() - 1], lhs - sum_i_deltas);

    out
}

/// TODO - Nat: This should be moved and made private
pub fn compute_lagrange_coefficient<C: Ciphersuite>(
    helpers: &[Identifier<C>],
    participant: Identifier<C>,
    helper_i: Identifier<C>,
) -> Scalar<C> {
    let mut num = <<C::Group as Group>::Field>::one();
    let mut den = <<C::Group as Group>::Field>::one();

    for j in helpers.iter() {
        if helper_i == *j {
            continue;
        }

        num *= participant - *j;
        den *= helper_i - *j;
    }

    num * <<C::Group as Group>::Field>::invert(&den).unwrap()
}

/// # Communication round 1
/// # Helper i sends i_deltas[j] to helper j

/// # deltas: all i_deltas received from each helper i in the communication round
/// # Output: sigma_j

pub fn compute_sigmas_to_repair_share<C: Ciphersuite>(deltas_j: &[Scalar<C>]) -> Scalar<C> {
    let mut sigma_j = <<C::Group as Group>::Field>::zero();

    for d in deltas_j {
        sigma_j = sigma_j + *d;
    }

    sigma_j
}

/// # Communication round 2
/// # Helper j sends sigma_j to participant r

/// # sigmas: all sigma_j received from each helper j
/// # Output: share_r: r's secret share

pub fn repair_share<C: Ciphersuite>(
    sigmas: &[Scalar<C>],
    identifier: Identifier<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> SecretShare<C> {
    let mut share = <<C::Group as Group>::Field>::zero();

    for s in sigmas {
        share = share + *s;
    }

    SecretShare {
        identifier,
        value: SigningShare(share),
        commitment: commitment.clone(),
    }
}
