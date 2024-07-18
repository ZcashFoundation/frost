//! Refresh Shares
//!
//! Implements the functionality to refresh a share. This requires the participation
//! of all the remaining signers. This can be done using a Trusted Dealer or
//! DKG (not yet implemented)

use alloc::vec::Vec;
use alloc::collections::BTreeMap;

use crate::{
    keys::{
        generate_coefficients, generate_secret_shares, validate_num_of_signers,
        CoefficientCommitment, PublicKeyPackage, SigningKey, SigningShare, VerifyingShare,
    },
    Ciphersuite, CryptoRng, Error, Field, Group, Identifier, RngCore,
};

use super::{KeyPackage, SecretShare, VerifiableSecretSharingCommitment};

/// Generates new zero key shares and a public key package using a trusted dealer
/// Building a new public key package is done by taking the verifying shares from the new public key package and adding
/// them to the original verifying shares
pub fn compute_refreshing_shares<C: Ciphersuite, R: RngCore + CryptoRng>(
    old_pub_key_package: PublicKeyPackage<C>,
    max_signers: u16,
    min_signers: u16,
    identifiers: &[Identifier<C>],
    rng: &mut R,
) -> Result<(Vec<SecretShare<C>>, PublicKeyPackage<C>), Error<C>> {
    // Validate inputs
    if identifiers.len() != max_signers as usize {
        return Err(Error::IncorrectNumberOfIdentifiers);
    }

    validate_num_of_signers(min_signers, max_signers)?;

    // Build zero key shares
    let zero_key = SigningKey {
        scalar: <<C::Group as Group>::Field>::zero(),
    };

    let coefficients = generate_coefficients::<C, R>(min_signers as usize - 1, rng);

    let zero_shares = generate_secret_shares(
        &zero_key,
        max_signers,
        min_signers,
        coefficients,
        identifiers,
    )?;

    let mut verifying_shares: BTreeMap<Identifier<C>, VerifyingShare<C>> = BTreeMap::new();
    let mut zero_shares_minus_identity: Vec<SecretShare<C>> = Vec::new();

    for share in zero_shares.clone() {
        let zero_verifying_share: VerifyingShare<C> = SigningShare::into(share.signing_share);

        let old_verifying_share = old_pub_key_package.verifying_shares.get(&share.identifier);

        match old_verifying_share {
            Some(old_verifying_share) => {
                let verifying_share =
                    zero_verifying_share.to_element() + old_verifying_share.to_element();
                verifying_shares.insert(share.identifier, VerifyingShare::new(verifying_share));
            }
            None => return Err(Error::UnknownIdentifier),
        };

        let mut coefficients = share.commitment.0;
        coefficients.remove(0);
        zero_shares_minus_identity.push(SecretShare {
            header: share.header,
            identifier: share.identifier,
            signing_share: share.signing_share,
            commitment: VerifiableSecretSharingCommitment::new(coefficients),
        });
    }

    let pub_key_package = PublicKeyPackage::<C> {
        header: old_pub_key_package.header,
        verifying_shares,
        verifying_key: old_pub_key_package.verifying_key,
    };

    Ok((zero_shares_minus_identity, pub_key_package))
}

/// Each participant refreshes their shares
/// This is done by taking the `zero_share` received from the trusted dealer and adding it to the original share
pub fn refresh_share<C: Ciphersuite>(
    zero_share: SecretShare<C>,
    current_key_package: &KeyPackage<C>,
) -> Result<KeyPackage<C>, Error<C>> {
    // The identity commitment needs to be added to the VSS commitment
    let identity_commitment: Vec<CoefficientCommitment<C>> =
        vec![CoefficientCommitment::new(C::Group::identity())];

    let zero_commitments_without_id = zero_share.commitment.0;

    let zero_commitment: Vec<CoefficientCommitment<C>> = identity_commitment
        .into_iter()
        .chain(zero_commitments_without_id.clone())
        .collect();

    let zero_share = SecretShare {
        header: zero_share.header,
        identifier: zero_share.identifier,
        signing_share: zero_share.signing_share,
        commitment: VerifiableSecretSharingCommitment::<C>::new(zero_commitment),
    };

    // verify zero_share secret share
    let zero_key_package = KeyPackage::<C>::try_from(zero_share)?;

    let signing_share: SigningShare<C> = SigningShare::new(
        zero_key_package.signing_share.to_scalar() + current_key_package.signing_share.to_scalar(),
    );

    let mut new_key_package = current_key_package.clone();
    new_key_package.signing_share = signing_share;

    Ok(new_key_package)
}
