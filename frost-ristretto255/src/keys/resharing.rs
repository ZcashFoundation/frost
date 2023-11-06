//! TODO

use std::collections::BTreeMap;

use crate::Error;
use crate::{frost, CryptoRng, Identifier, RngCore};

use super::{KeyPackage, PublicKeyPackage, SecretShare, SigningShare};

/// TODO
pub type SecretSubshare = SecretShare;

/// TODO
pub fn reshare_step_1<R: RngCore + CryptoRng>(
    share_i: &SigningShare,
    rng: &mut R,
    new_threshold: u16,
    new_idents: &[Identifier],
) -> Result<BTreeMap<Identifier, SecretSubshare>, Error> {
    frost::keys::resharing::reshare_step_1(share_i, rng, new_threshold, new_idents)
}

/// TODO
pub fn reshare_step_2(
    our_ident: Identifier,
    old_pubkeys: &PublicKeyPackage,
    new_threshold: u16,
    new_idents: &[Identifier],
    received_subshares: &BTreeMap<Identifier, SecretSubshare>,
) -> Result<(KeyPackage, PublicKeyPackage), Error> {
    frost::keys::resharing::reshare_step_2(
        our_ident,
        old_pubkeys,
        new_threshold,
        new_idents,
        received_subshares,
    )
}
