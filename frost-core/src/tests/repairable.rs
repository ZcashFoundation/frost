//! Test for Repairable Threshold Scheme

use debugless_unwrap::DebuglessUnwrap;
use rand_core::{CryptoRng, RngCore};

use crate::{
    frost::{
        self,
        keys::{
            generate_coefficients, repairable::compute_random_values,
            repairable::compute_sum_of_random_values, PublicKeyPackage, SecretShare,
        },
        Identifier,
    },
    Ciphersuite, Field, Group, Scalar,
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

fn generate_scalars_from_byte_strings<C: Ciphersuite>(
    bs: &str,
) -> <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar {
    let decoded = hex::decode(bs).unwrap();
    let out = <<C::Group as Group>::Field>::deserialize(&decoded.try_into().debugless_unwrap());
    out.unwrap()
}

/// Test compute_sum_of_random_values
pub fn check_compute_sum_of_random_values<C: Ciphersuite>() {
    let value_1 = generate_scalars_from_byte_strings::<C>(
        "44260f9f457d96bd0dcdcd9b83c45231bca28ecc5ab52dee9cf59f6b361c520c",
    );
    let value_2 = generate_scalars_from_byte_strings::<C>(
        "9babf5fa9a6ea4bf9486e796115dc767a1bdd27cd2834b6d5f29c988ffebe508",
    );
    let value_3 = generate_scalars_from_byte_strings::<C>(
        "3e62e7461db9ca1ed2f1549a8114bbc87fa9242ce0012ed3f9ac9dcf23f4c30a",
    );

    let expected: Scalar<C> = compute_sum_of_random_values::<C>(&[value_1, value_2, value_3]);

    let actual: <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar =
        generate_scalars_from_byte_strings::<C>(
            "3060f683e341f3439ea8122a383cf64cdd0986750d3ba72ef6cb06c459fcfb0f",
        );

    assert!(actual == expected);
}
