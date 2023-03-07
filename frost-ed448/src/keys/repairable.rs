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
    let out = frost::keys::repairable::generate_random_values(identifier, max_signers, min_signers, &mut rng);
    out
}
