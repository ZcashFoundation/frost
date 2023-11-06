//! Dynamic resharing of FROST signing keys.
//!
//! Implements [Wang's Verifiable Secret Resharing (VSR) Scheme
#![doc = "](https://www.semanticscholar.org/paper/Verifiable-Secret-Redistribution\
-for-Threshold-Wong-Wang/48d248779002b0015bdb99841a43395b526d5f8e)."]
//! FROST signing shares can be periodically rotated among signers to
//! protect against mobile and active adversaries. This allows old shares
//! to be 'revoked' (although only in a soft manner) and replaced with new shares.
//!
//! As a byproduct, resharing allows signers to change parameters of their
//! signing group, including setting a new threshold, changing identifiers,
//! adding new signers or excluding old signers from the new group of shares.
//! Resharing can be done even if some signers are offline; as long as the
//! signing threshold is met, the joint secret can be redistributed with new
//! shares and potentially a new threshold.
//!
//! Shares issued from before and after the resharing are mutually incompatible,
//! so it is imperative that at least the one threshold-subset of signers ACK
//! the resharing as successful before anyone deletes their old shares. See
//! [`reshare_step_2`] for more info.
//!
//! After a resharing occurs, the old shares are still usable. Normally, signers
//! are advised to delete their old shares, but nothing prevents them from keeping
//! the outdated shares either by maliciousness or through honest mistake.
//!
//! Downstream consumers should consider how inactive signers will be notified
//! about a resharing which occurrs while they are offline.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    compute_lagrange_coefficient, Ciphersuite, CryptoRng, Error, Field, Group, Identifier, RngCore,
    Scalar,
};

use super::{
    evaluate_vss, split, validate_num_of_signers, CoefficientCommitment, IdentifierList,
    KeyPackage, PublicKeyPackage, SecretShare, SigningKey, SigningShare,
    VerifiableSecretSharingCommitment, VerifyingShare,
};

/// A subshare of a secret share. This contains the same data
/// as a [`SecretShare`], except it is actually a share of a share,
/// used in the process of resharing.
pub type SecretSubshare<C> = SecretShare<C>;

/// Split a secret signing share into a set of secret subshares (shares of a share).
///
/// `share_i` is our FROST signing share, which will be split into subshares.
///
/// `new_threshold` is the desired new minimum signer threshold after resharing.
/// All signers participating in resharing must specify the same `new_threshold`.
///
/// `new_idents` is a list of identifiers for peers to whom the secret subshares
/// will be distributed. Depending on use-case, these identifiers may be completely
/// new, or they may be the same as the old signing group from before resharing.
///
/// The resulting output maps peers' identifiers to the subshare which they should
/// receive. The commitment in each subshare is the same, and should be broadcast
/// to all subshare recipients. The secret subshare itself should be sent via
/// a private authenticated channel to the specific recipient which maps to it.
pub fn reshare_step_1<C: Ciphersuite, R: RngCore + CryptoRng>(
    share_i: &SigningShare<C>,
    rng: &mut R,
    new_threshold: u16,
    new_idents: &[Identifier<C>],
) -> Result<BTreeMap<Identifier<C>, SecretSubshare<C>>, Error<C>> {
    let (subshares, _) = split(
        &SigningKey::from_scalar(share_i.0),
        new_idents.len() as u16,
        new_threshold,
        IdentifierList::Custom(new_idents),
        rng,
    )?;

    Ok(subshares)
}

/// Verify and combine a set of secret subshares into a new FROST signing share.
///
/// `our_ident` is the identifier for ourself.
///
/// `old_pubkeys` is the old public key package for the group's joint FROST key.
///
/// `new_threshold` is the desired new minimum signer threshold after resharing.
/// All signers participating in resharing must specify the same `new_threshold`.
///
/// `new_idents` is the list of identifiers for peers to whom the secret subshares
/// are being distributed. Depending on use-case, these identifiers may be completely
/// new, or they may be the same as the old signing group from before resharing.
///
/// `received_subshares` maps identifiers to the secret subshare sent by those peers.
/// We assume the commitment in each subshare is consistent with a commitment publicly
/// broadcasted by the sender, i.e. we assume each peer has not equivocated by sending
/// inconsistent commitments to different subshare recipients.
///
/// The output is a new FROST secret signing share and public key package. The joint
/// public key will match the old joint public key, but the signing and verification
/// shares will be changed and will no longer be compatible with old shares from
/// before the resharing occurred.
///
/// The caller MUST ensure at least `new_threshold` signers ACK the resharing as successful.
/// We recommend having each signer broadcast their public verification shares to confirm
/// the new set of shares are all consistent. Only then can the previous shares be safely
/// overwritten.
pub fn reshare_step_2<C: Ciphersuite>(
    our_ident: Identifier<C>,
    old_pubkeys: &PublicKeyPackage<C>,
    new_threshold: u16,
    new_idents: &[Identifier<C>],
    received_subshares: &BTreeMap<Identifier<C>, SecretSubshare<C>>,
) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), Error<C>> {
    validate_num_of_signers(new_threshold, new_idents.len() as u16)?;
    for (sender_ident, subshare) in received_subshares.into_iter() {
        // Ensure each subshare is from a member of the group.
        let verifying_share = old_pubkeys
            .verifying_shares
            .get(sender_ident)
            .ok_or(Error::UnknownIdentifier)?;

        // Constant term of the commitment MUST be the same as the sender's own
        // public share. If this fails, the `old_pubkeys` is internally inconsistent.
        if subshare.commitment.coefficients()[0].value() != verifying_share.to_element() {
            return Err(Error::IncorrectCommitment)?; // TODO add culprit
        }

        // Every peer's resharing polynomial must have degree `t' - 1`.
        if subshare.commitment.coefficients().len() != new_threshold as usize {
            return Err(Error::InvalidCoefficients); // TODO add culprit
        }
    }

    let old_idents: BTreeSet<Identifier<C>> = received_subshares.keys().copied().collect();
    let lagrange_coefficients: BTreeMap<Identifier<C>, Scalar<C>> = old_idents
        .iter()
        .map(|&id| -> Result<(Identifier<C>, Scalar<C>), Error<C>> {
            let l = compute_lagrange_coefficient(&old_idents, None, id)?;
            Ok((id, l))
        })
        .collect::<Result<_, Error<C>>>()?;

    let group_pubkey = received_subshares
        .into_iter()
        .map(|(id, subshare)| {
            subshare.commitment.coefficients()[0].value() * lagrange_coefficients[id]
        })
        .reduce(|sum, term| sum + term)
        .ok_or(Error::IncorrectNumberOfShares)?; // At least one subshare is required.

    // The pubkeys participating in resharing must represent at least the old
    // threshold `t` of the group. The interpolated pubkey will not match here
    // unless that threshold is met.
    if group_pubkey != old_pubkeys.verifying_key.to_element() {
        return Err(Error::IncorrectNumberOfShares);
    }

    let mut new_share_sum = <C::Group as Group>::Field::zero();

    for (sender_ident, subshare) in received_subshares.into_iter() {
        // Verify the subshare against the commitment.
        //   s_{ij} * G == G * ( s_i + a_1*j + a_2 * j^2 + ... + a_{t'-1} * j^{t'-1} )
        let s = subshare.signing_share.to_scalar();
        if C::Group::generator() * s != evaluate_vss(our_ident, &subshare.commitment) {
            return Err(Error::InvalidSecretShare); // TODO add culprit
        }

        // The new share is computed by interpolating the constant coefficient of a
        // new polynomial generated jointly by the signers who participated in resharing.
        new_share_sum = new_share_sum + s * lagrange_coefficients[sender_ident];
    }

    let new_signing_share = SigningShare(new_share_sum);

    // The group's new public polynomial coefficients can be computed by treating commitment
    // coefficients as polynomial evaluations and interpolating the resulting function.
    // See Step 8 here: https://conduition.io/cryptography/shamir-resharing/#Resharing
    let new_group_commit_coeffs: Vec<CoefficientCommitment<C>> = (0..new_threshold as usize)
        .map(|k| {
            received_subshares
                .iter()
                .fold(C::Group::identity(), |sum, (id, subshare)| {
                    sum + subshare.commitment.coefficients()[k].value() * lagrange_coefficients[id]
                })
        })
        .map(CoefficientCommitment)
        .collect();

    // The new group commitment should match the group pubkey.
    if new_group_commit_coeffs[0].value() != old_pubkeys.verifying_key.to_element() {
        return Err(Error::IncorrectCommitment);
    }

    let new_group_commitment = VerifiableSecretSharingCommitment(new_group_commit_coeffs);

    let new_verifying_shares: BTreeMap<Identifier<C>, VerifyingShare<C>> = new_idents
        .into_iter()
        .map(|&id| (id, VerifyingShare(evaluate_vss(id, &new_group_commitment))))
        .collect();

    // Our identifier must be one of the intended resharing recipients.
    let new_verifying_share = new_verifying_shares
        .get(&our_ident)
        .ok_or(Error::UnknownIdentifier)?
        .clone();

    // Sanity check; our new share should be valid for the new commitment.
    if C::Group::generator() * new_share_sum != new_verifying_share.to_element() {
        return Err(Error::InvalidSecretShare);
    }

    let new_pubkey_pkg = PublicKeyPackage::new(new_verifying_shares, old_pubkeys.verifying_key);

    let new_secret_key_package = KeyPackage::new(
        our_ident,
        new_signing_share,
        new_verifying_share,
        old_pubkeys.verifying_key,
        new_threshold,
    );

    Ok((new_secret_key_package, new_pubkey_pkg))
}
