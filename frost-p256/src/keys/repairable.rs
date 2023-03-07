//! Repairable Threshold Scheme

#![doc = include_str!("../../repairable.md")]

/// Generate random values for each helper - 1 for use in computing the value for the final helper

pub fn generate_random_values<R: RngCore + CryptoRng>(
    helpers: &[Identifier<C>],
    share_i: &SecretShare<C>,
    zeta_i: Scalar<C>,
    rng: &mut R,
) -> HashMap<Identifier<C>, Scalar<C>> {
    frost::keys::repairable::generate_random_values(identifier, max_signers, min_signers, &mut rng)
}
