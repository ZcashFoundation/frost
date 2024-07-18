//! Refresh Shares
//!
//! Implements the functionality to refresh a share. This requires the participation
//! of all the remaining signers. This can be done using a Trusted Dealer or
//! DKG (not yet implemented)

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::{
    keys::{
        generate_coefficients, generate_secret_shares, validate_num_of_signers,
        CoefficientCommitment, PublicKeyPackage, SigningKey, SigningShare, VerifyingShare,
    },
    Ciphersuite, CryptoRng, Error, Field, Group, Identifier, RngCore,
};

use super::{KeyPackage, SecretShare, VerifiableSecretSharingCommitment};

/// Generates new zero key shares and a public key package using a trusted
/// dealer Building a new public key package is done by taking the verifying
/// shares from the new public key package and adding them to the original
/// verifying shares
pub fn compute_refreshing_shares<C: Ciphersuite, R: RngCore + CryptoRng>(
    pub_key_package: PublicKeyPackage<C>,
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

    // Build refreshing shares
    let refreshing_key = SigningKey {
        scalar: <<C::Group as Group>::Field>::zero(),
    };

    let coefficients = generate_coefficients::<C, R>(min_signers as usize - 1, rng);
    let refreshing_shares = generate_secret_shares(
        &refreshing_key,
        max_signers,
        min_signers,
        coefficients,
        identifiers,
    )?;

    let mut refreshed_verifying_shares: BTreeMap<Identifier<C>, VerifyingShare<C>> =
        BTreeMap::new();
    let mut refreshing_shares_minus_identity: Vec<SecretShare<C>> = Vec::new();

    for mut share in refreshing_shares {
        let refreshing_verifying_share: VerifyingShare<C> = SigningShare::into(share.signing_share);

        let verifying_share = pub_key_package.verifying_shares.get(&share.identifier);

        match verifying_share {
            Some(verifying_share) => {
                let refreshed_verifying_share =
                    refreshing_verifying_share.to_element() + verifying_share.to_element();
                refreshed_verifying_shares.insert(
                    share.identifier,
                    VerifyingShare::new(refreshed_verifying_share),
                );
            }
            None => return Err(Error::UnknownIdentifier),
        };

        share.commitment.0.remove(0);
        refreshing_shares_minus_identity.push(share);
    }

    let refreshed_pub_key_package = PublicKeyPackage::<C> {
        header: pub_key_package.header,
        verifying_shares: refreshed_verifying_shares,
        verifying_key: pub_key_package.verifying_key,
    };

    Ok((refreshing_shares_minus_identity, refreshed_pub_key_package))
}

/// Each participant refreshes their shares This is done by taking the
/// `refreshing_share` received from the trusted dealer and adding it to the
/// original share
pub fn refresh_share<C: Ciphersuite>(
    mut refreshing_share: SecretShare<C>,
    current_key_package: &KeyPackage<C>,
) -> Result<KeyPackage<C>, Error<C>> {
    // The identity commitment needs to be added to the VSS commitment
    let identity_commitment: Vec<CoefficientCommitment<C>> =
        vec![CoefficientCommitment::new(C::Group::identity())];

    let refreshing_share_commitments: Vec<CoefficientCommitment<C>> = identity_commitment
        .into_iter()
        .chain(refreshing_share.commitment.0.clone())
        .collect();

    refreshing_share.commitment =
        VerifiableSecretSharingCommitment::<C>::new(refreshing_share_commitments);

    // Verify refreshing_share secret share
    let refreshed_share_package = KeyPackage::<C>::try_from(refreshing_share)?;

    let signing_share: SigningShare<C> = SigningShare::new(
        refreshed_share_package.signing_share.to_scalar()
            + current_key_package.signing_share.to_scalar(),
    );

    let mut new_key_package = current_key_package.clone();
    new_key_package.signing_share = signing_share;

    Ok(new_key_package)
}
