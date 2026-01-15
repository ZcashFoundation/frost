//! Repairable Threshold Scheme
//!
//! Implements the Repairable Threshold Scheme (RTS) from <https://eprint.iacr.org/2017/1155>.
//! The RTS is used to help a signer (participant) repair their lost share. This is achieved
//! using a subset of the other signers known here as `helpers`.

use alloc::collections::{BTreeMap, BTreeSet};

use alloc::vec::Vec;

use crate::{
    compute_lagrange_coefficient, Ciphersuite, CryptoRng, Error, Field, Group, Header, Identifier,
    RngCore, Scalar,
};

use super::{generate_coefficients, SecretShare, SigningShare, VerifiableSecretSharingCommitment};

/// Step 1 of RTS.
///
/// Generates the "delta" values from `helper_i` to help `participant` recover their share
/// where `helpers` contains the identifiers of all the helpers (including `helper_i`), and `share_i`
/// is the share of `helper_i`.
///
/// Returns a BTreeMap mapping which value should be sent to which participant.
pub fn repair_share_step_1<C: Ciphersuite, R: RngCore + CryptoRng>(
    helpers: &[Identifier<C>],
    share_i: &SecretShare<C>,
    rng: &mut R,
    participant: Identifier<C>,
) -> Result<BTreeMap<Identifier<C>, Scalar<C>>, Error<C>> {
    if helpers.len() < 2 {
        return Err(Error::InvalidMinSigners);
    }

    if helpers.is_empty() {
        return Err(Error::IncorrectNumberOfIdentifiers);
    }
    let xset: BTreeSet<_> = helpers.iter().cloned().collect();
    if xset.len() != helpers.len() {
        return Err(Error::DuplicatedIdentifier);
    }

    let rand_val: Vec<Scalar<C>> = generate_coefficients::<C, R>(helpers.len() - 1, rng);

    compute_last_random_value(&xset, share_i, &rand_val, participant)
}

/// Compute the last delta value given the (generated uniformly at random) remaining ones
/// since they all must add up to `zeta_i * share_i`.
///
/// Returns a BTreeMap mapping which value should be sent to which participant.
fn compute_last_random_value<C: Ciphersuite>(
    helpers: &BTreeSet<Identifier<C>>,
    share_i: &SecretShare<C>,
    random_values: &Vec<Scalar<C>>,
    participant: Identifier<C>,
) -> Result<BTreeMap<Identifier<C>, Scalar<C>>, Error<C>> {
    // Calculate Lagrange Coefficient for helper_i
    let zeta_i = compute_lagrange_coefficient(helpers, Some(participant), share_i.identifier)?;

    let lhs = zeta_i * share_i.signing_share.to_scalar();

    let mut out: BTreeMap<Identifier<C>, Scalar<C>> = helpers
        .iter()
        .copied()
        .zip(random_values.iter().copied())
        .collect();

    let mut sum_i_deltas = <<C::Group as Group>::Field>::zero();

    for v in random_values {
        sum_i_deltas = sum_i_deltas + *v;
    }

    out.insert(
        *helpers.last().ok_or(Error::IncorrectNumberOfIdentifiers)?,
        lhs - sum_i_deltas,
    );

    Ok(out)
}

// Communication round
//
// `helper_i` sends 1 `delta_j` to all other helpers (j)
// `helper_i` retains 1 `delta_j`

/// Step 2 of RTS.
///
/// Generates the `sigma` values from all `deltas` received from `helpers`
/// to help `participant` recover their share.
/// `sigma` is the sum of all received `delta` and the `delta_i` generated for `helper_i`.
///
/// Returns a scalar
pub fn repair_share_step_2<C: Ciphersuite>(deltas_j: &[Scalar<C>]) -> Scalar<C> {
    let mut sigma_j = <<C::Group as Group>::Field>::zero();

    for d in deltas_j {
        sigma_j = sigma_j + *d;
    }

    sigma_j
}

// Communication round
//
// `helper_j` sends 1 `sigma_j` to the `participant` repairing their share.

/// Step 3 of RTS
///
/// The `participant` sums all `sigma_j` received to compute the `share`. The `SecretShare`
/// is made up of the `identifier`and `commitment` of the `participant` as well as the
/// `value` which is the `SigningShare`.
pub fn repair_share_step_3<C: Ciphersuite>(
    sigmas: &[Scalar<C>],
    identifier: Identifier<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> SecretShare<C> {
    let mut share = <<C::Group as Group>::Field>::zero();

    for s in sigmas {
        share = share + *s;
    }

    SecretShare {
        header: Header::default(),
        identifier,
        signing_share: SigningShare::new(share),
        commitment: commitment.clone(),
    }
}
