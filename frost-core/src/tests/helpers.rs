//! Helper function for testing

use crate::{Ciphersuite, Field, Group};
use rand_core::{CryptoRng, RngCore};

/// Helper function for randomly generating an element
pub fn generate_element<C: Ciphersuite, R: RngCore + CryptoRng>(
    rng: &mut R,
) -> <<C as Ciphersuite>::Group as Group>::Element {
    let scalar = <<C::Group as Group>::Field>::random(rng);
    <C::Group>::generator() * scalar
}
