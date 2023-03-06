//! Test for Repairable Threshold Scheme

use rand_core::{CryptoRng, RngCore};

use crate::{
    frost::{
        self,
        keys::{
            generate_coefficients, repairable::compute_random_values, PublicKeyPackage, SecretShare,
        },
        Identifier,
    },
    Ciphersuite, Field, Group,
};

/// Test RTS.
pub fn check_rts<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    // We want to test that recover share matches the original share

    // Compute shares

    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;
    let (shares, _pubkeys): (Vec<SecretShare<C>>, PublicKeyPackage<C>) =
        frost::keys::keygen_with_dealer(max_signers, min_signers, &mut rng).unwrap();

    // // Verifies the secret shares from the dealer
    // let key_packages: HashMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> = shares
    //     .into_iter()
    //     .map(|share| {
    //         (
    //             share.identifier,
    //             frost::keys::KeyPackage::try_from(share).unwrap(),
    //         )
    //     })
    //     .collect();

    // Try to recover a share

    // Signer 2 will lose their share
    // Signer 1, 4 and 5 will help signer 2 to recover their share

    let helpers: [Identifier<C>; 3] = [
        Identifier::try_from(1).unwrap(),
        Identifier::try_from(4).unwrap(),
        Identifier::try_from(5).unwrap(),
    ];
    //  For every helper i in helpers:

    let random_values = generate_coefficients::<C, R>(2, &mut rng);

    for i in [1usize, 4, 5] {
        // let identifier: Identifier<C> = Identifier::try_from(i as u16).unwrap();
        // pub fn compute_random_values(i, helpers, share_i, zeta_i) -> deltas_i
        let zeta_i = <<C::Group as Group>::Field>::one();
        let deltas_i = compute_random_values(&helpers, &shares[i - 1], zeta_i, &random_values);

        // Test if Sum of deltas_i = zeta_i * share _i
        let lhs = zeta_i * shares[i - 1].value.0;
        let mut rhs = <<C::Group as Group>::Field>::zero();
        for (_k, v) in deltas_i {
            rhs = rhs + v;
        }

        assert!(lhs == rhs);
    }
}
