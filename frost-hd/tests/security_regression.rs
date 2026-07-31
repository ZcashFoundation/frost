//! Executable documentation of the fundamental related-key property.

use frost_core::{Ciphersuite, Field, Group};
use frost_ed25519::{Ed25519Sha512, Ed25519ScalarField};

#[test]
fn public_child_tweak_recovers_the_parent_participant_share() {
    type C = Ed25519Sha512;
    let parent = <Ed25519ScalarField as Field>::one();
    let tweak = C::H1(b"public deterministic child tweak");
    let child = parent + tweak;
    let recovered_parent = child - tweak;
    assert_eq!(recovered_parent, parent);

    let parent_public = <C::Group as Group>::generator() * parent;
    let child_public = parent_public + <C::Group as Group>::generator() * tweak;
    assert_eq!(
        child_public - <C::Group as Group>::generator() * tweak,
        parent_public
    );
}
