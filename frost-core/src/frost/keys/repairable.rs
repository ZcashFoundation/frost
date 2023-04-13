//! Repairable Threshold Scheme
//!
//! Implements the Repairable Threshold Scheme (RTS) from [https://eprint.iacr.org/2017/1155].
//! The RTS is used to help a signer (participant) repair their lost share. This is achieved
//! using a subset of the other signers know here as `helpers`.

use std::collections::HashMap;

use crate::{frost::Identifier, Ciphersuite, CryptoRng, Field, Group, RngCore, Scalar};

use super::{generate_coefficients, SecretShare, SigningShare, VerifiableSecretSharingCommitment};

/// Step 1 of RTS.
///
/// Generates the "delta" values from `helper_i` to help `participant` recover their share
/// where `helpers` contains the identifiers of all the helpers (including `helper_i`), and `share_i`
/// is the share of `helper_i`.
///
/// Returns a HashMap mapping which value should be sent to which participant.
pub fn repair_share_step_1<C: Ciphersuite, R: RngCore + CryptoRng>(
    helpers: &[Identifier<C>],
    share_i: &SecretShare<C>,
    rng: &mut R,
    participant: Identifier<C>,
    helper_i: Identifier<C>,
) -> HashMap<Identifier<C>, Scalar<C>> {
    let rand_val: Vec<Scalar<C>> = generate_coefficients::<C, R>(helpers.len() - 1, rng);

    compute_last_random_value(helpers, share_i, &rand_val, participant, helper_i)
}

/// Compute the last delta value given the (generated uniformly at random) remaining ones
/// since they all must add up to `zeta_i * share_i`.
///
/// Returns a HashMap mapping which value should be sent to which participant.
fn compute_last_random_value<C: Ciphersuite>(
    helpers: &[Identifier<C>],
    share_i: &SecretShare<C>,
    random_values: &Vec<Scalar<C>>,
    participant: Identifier<C>,
    helper_i: Identifier<C>,
) -> HashMap<Identifier<C>, Scalar<C>> {
    // Calculate Lagrange Coefficient for helper_i
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

/// Compute the i-th Lagrange coefficient evaluated at `participant`, i.e.
/// computes `zeta_i` such that f(participant) is the sum of all `zeta_i * share_i`
/// for each `i` in `helpers`.
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

/// Step 2 of RTS: Communication round
///
/// `helper_i` sends 1 `delta_j` to all other helpers (j)
/// `helper_i` retains 1 `delta_j`

/// Step 3 of RTS.
///
/// Generates the `sigma` values from all `deltas` received from `helpers`
/// to help `participant` recover their share.
/// `sigma` is the sum of all received `delta` and the `delta_i` generated for `helper_i`.
///
/// Returns a scalar
pub fn repair_share_step_3<C: Ciphersuite>(deltas_j: &[Scalar<C>]) -> Scalar<C> {
    let mut sigma_j = <<C::Group as Group>::Field>::zero();

    for d in deltas_j {
        sigma_j = sigma_j + *d;
    }

    sigma_j
}

/// Step 4 of RTS: Communication round
///
/// `helper_j` sends 1 `sigma_j` to the `participant` repairing their share.

/// Step 5 of RTS
///
/// The `participant` sums all `sigma_j` received to compute the `share`. The `SecretShare`
/// is made up of the `identifier`and `commitment` of the `participant` as well as the
/// `value` which is the `SigningShare`.
pub fn repair_share_step_5<C: Ciphersuite>(
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
