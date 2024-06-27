//! Refresh Shares
//!
//! Implements the functionality to refresh a share. This requires the participation
//! of all the remaining signers. This can be done using a Trusted Dealer or
//! DKG (not yet implemented)

use std::collections::BTreeMap;

use crate::{
    keys::{
        generate_coefficients, generate_secret_shares, validate_num_of_signers,
        CoefficientCommitment, PublicKeyPackage, SigningKey, SigningShare, VerifyingShare,
    },
    Ciphersuite, CryptoRng, Error, Field, Group, Identifier, RngCore, Scalar,
};

use super::{SecretShare, VerifiableSecretSharingCommitment};

/// Refreshes shares using a trusted dealer
pub fn calculate_zero_key<C: Ciphersuite, R: RngCore + CryptoRng>(
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
        let signer_public = SigningShare::into(share.signing_share);
        verifying_shares.insert(share.identifier, signer_public);
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
    current_share: &SecretShare<C>,
) -> Result<SecretShare<C>, Error<C>> {
    let signing_share: Scalar<C> =
        zero_share.signing_share.to_scalar() + current_share.signing_share.to_scalar();

    // The identity commitment needs to be added to the VSS commitment
    let identity_commitment: Vec<CoefficientCommitment<C>> =
        vec![(CoefficientCommitment(<C::Group>::identity()))];

    let zero_commitments_without_id = zero_share.commitment.0;
    let old_commitments = current_share.commitment.0.clone();

    let zero_commitment: Vec<CoefficientCommitment<C>> = identity_commitment
        .into_iter()
        .chain(zero_commitments_without_id.clone())
        .collect();

    let mut commitments: Vec<CoefficientCommitment<C>> = Vec::with_capacity(zero_commitment.len());

    if old_commitments.len() >= zero_commitment.len() {
        for i in 0..zero_commitment.len() {
            if let (Some(zero_commitment), Some(old_commitment)) =
                (zero_commitment.get(i), old_commitments.get(i))
            {
                commitments.push(CoefficientCommitment::new(
                    zero_commitment.0 + old_commitment.0,
                ));
            } else {
                return Err(Error::IncorrectNumberOfCommitments);
            }
        }
    } else {
        return Err(Error::MissingCommitment);
    }

    let commitment = VerifiableSecretSharingCommitment::new(commitments);

    let signing_share = SigningShare::new(signing_share);

    Ok(SecretShare {
        header: zero_share.header,
        identifier: zero_share.identifier,
        signing_share,
        commitment,
    })
}
