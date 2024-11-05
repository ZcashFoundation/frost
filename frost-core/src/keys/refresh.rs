//! Refresh Shares
//!
//! Implements the functionality to refresh a share. This requires the participation
//! of all the remaining signers. This can be done using a Trusted Dealer or
//! DKG (not yet implemented)

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::{
    keys::dkg::{compute_proof_of_knowledge, round1, round2},
    keys::{
        evaluate_polynomial, generate_coefficients, generate_secret_polynomial,
        generate_secret_shares, validate_num_of_signers, CoefficientCommitment, PublicKeyPackage,
        SigningKey, SigningShare, VerifyingShare,
    },
    Ciphersuite, CryptoRng, Error, Field, Group, Header, Identifier, RngCore,
};

use core::iter;

use super::{dkg::round1::Package, KeyPackage, SecretShare, VerifiableSecretSharingCommitment};

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

/// Part 1 of refresh share with DKG. A refreshing_key is generated and a new package and secret_package are generated.
/// The identity commitment is removed from the packages.
pub fn refresh_dkg_part_1<C: Ciphersuite, R: RngCore + CryptoRng>(
    identifier: Identifier<C>,
    max_signers: u16,
    min_signers: u16,
    mut rng: R,
) -> Result<(round1::SecretPackage<C>, round1::Package<C>), Error<C>> {
    validate_num_of_signers::<C>(min_signers, max_signers)?;

    // Build refreshing shares
    let refreshing_key = SigningKey {
        scalar: <<C::Group as Group>::Field>::zero(),
    };

    // Round 1, Step 1
    let coefficients = generate_coefficients::<C, R>(min_signers as usize - 1, &mut rng);

    let (coefficients, commitment) =
        generate_secret_polynomial(&refreshing_key, max_signers, min_signers, coefficients)?;

    // Remove identity element from coefficients
    let mut coeff_comms = commitment.0;
    coeff_comms.remove(0);
    let commitment = VerifiableSecretSharingCommitment::new(coeff_comms.clone());

    let proof_of_knowledge =
        compute_proof_of_knowledge(identifier, &coefficients, &commitment, &mut rng)?;

    let secret_package = round1::SecretPackage {
        identifier,
        coefficients: coefficients.clone(),
        commitment: commitment.clone(),
        min_signers,
        max_signers,
    };
    let package = round1::Package {
        header: Header::default(),
        commitment,
        proof_of_knowledge,
    };

    Ok((secret_package, package))
}

/// Part 2 of refresh share with DKG. The identity commitment needs to be added back into the secret package.
pub fn refresh_dkg_part2<C: Ciphersuite>(
    mut secret_package: round1::SecretPackage<C>,
    round1_packages: &BTreeMap<Identifier<C>, round1::Package<C>>,
) -> Result<
    (
        round2::SecretPackage<C>,
        BTreeMap<Identifier<C>, round2::Package<C>>,
    ),
    Error<C>,
> {
    if round1_packages.len() != (secret_package.max_signers - 1) as usize {
        return Err(Error::IncorrectNumberOfPackages);
    }

    // The identity commitment needs to be added to the VSS commitment for secret package
    let identity_commitment: Vec<CoefficientCommitment<C>> =
        vec![CoefficientCommitment::new(C::Group::identity())];

    let refreshing_secret_share_commitments: Vec<CoefficientCommitment<C>> = identity_commitment
        .into_iter()
        .chain(secret_package.commitment.0.clone())
        .collect();

    secret_package.commitment =
        VerifiableSecretSharingCommitment::<C>::new(refreshing_secret_share_commitments);

    let mut round2_packages = BTreeMap::new();

    for (sender_identifier, round1_package) in round1_packages {
        // The identity commitment needs to be added to the VSS commitment for every round 1 package
        let identity_commitment: Vec<CoefficientCommitment<C>> =
            vec![CoefficientCommitment::new(C::Group::identity())];

        let refreshing_share_commitments: Vec<CoefficientCommitment<C>> = identity_commitment
            .into_iter()
            .chain(round1_package.commitment.0.clone())
            .collect();

        if refreshing_share_commitments.clone().len() != secret_package.min_signers as usize {
            return Err(Error::IncorrectNumberOfCommitments);
        }

        let ell = *sender_identifier;

        // Round 1, Step 5
        // We don't need to verify the proof of knowledge

        // Round 2, Step 1
        //
        // > Each P_i securely sends to each other participant P_ℓ a secret share (ℓ, f_i(ℓ)),
        // > deleting f_i and each share afterward except for (i, f_i(i)),
        // > which they keep for themselves.
        let signing_share = SigningShare::from_coefficients(&secret_package.coefficients, ell);

        round2_packages.insert(
            ell,
            round2::Package {
                header: Header::default(),
                signing_share,
            },
        );
    }
    let fii = evaluate_polynomial(secret_package.identifier, &secret_package.coefficients);

    Ok((
        round2::SecretPackage {
            identifier: secret_package.identifier,
            commitment: secret_package.commitment,
            secret_share: fii,
            min_signers: secret_package.min_signers,
            max_signers: secret_package.max_signers,
        },
        round2_packages,
    ))
}

/// This is the step that actually refreshes the shares. New public key packages
/// and key packages are created.
pub fn refresh_dkg_shares<C: Ciphersuite>(
    round2_secret_package: &round2::SecretPackage<C>,
    round1_packages: &BTreeMap<Identifier<C>, round1::Package<C>>,
    round2_packages: &BTreeMap<Identifier<C>, round2::Package<C>>,
    old_pub_key_package: PublicKeyPackage<C>,
    old_key_package: KeyPackage<C>,
) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), Error<C>> {
    // Add identity commitment back into round1_packages
    let mut new_round_1_packages = BTreeMap::new();
    for (sender_identifier, round1_package) in round1_packages {
        // The identity commitment needs to be added to the VSS commitment for every round 1 package
        let identity_commitment: Vec<CoefficientCommitment<C>> =
            vec![CoefficientCommitment::new(C::Group::identity())];

        let refreshing_share_commitments: Vec<CoefficientCommitment<C>> = identity_commitment
            .into_iter()
            .chain(round1_package.commitment.0.clone())
            .collect();

        let new_commitments =
            VerifiableSecretSharingCommitment::<C>::new(refreshing_share_commitments);

        let new_round_1_package = Package {
            header: round1_package.header,
            commitment: new_commitments,
            proof_of_knowledge: round1_package.proof_of_knowledge,
        };

        new_round_1_packages.insert(*sender_identifier, new_round_1_package);
    }

    if new_round_1_packages.len() != (round2_secret_package.max_signers - 1) as usize {
        return Err(Error::IncorrectNumberOfPackages);
    }
    if new_round_1_packages.len() != round2_packages.len() {
        return Err(Error::IncorrectNumberOfPackages);
    }
    if new_round_1_packages
        .keys()
        .any(|id| !round2_packages.contains_key(id))
    {
        return Err(Error::IncorrectPackage);
    }

    let mut signing_share = <<C::Group as Group>::Field>::zero();

    for (sender_identifier, round2_package) in round2_packages {
        // Round 2, Step 2
        //
        // > Each P_i verifies their shares by calculating:
        // > g^{f_ℓ(i)} ≟ ∏^{t−1}_{k=0} φ^{i^k mod q}_{ℓk}, aborting if the
        // > check fails.
        let ell = *sender_identifier;
        let f_ell_i = round2_package.signing_share;

        let commitment = &new_round_1_packages
            .get(&ell)
            .ok_or(Error::PackageNotFound)?
            .commitment;

        // The verification is exactly the same as the regular SecretShare verification;
        // however the required components are in different places.
        // Build a temporary SecretShare so what we can call verify().
        let secret_share = SecretShare {
            header: Header::default(),
            identifier: round2_secret_package.identifier,
            signing_share: f_ell_i,
            commitment: commitment.clone(),
        };

        // Verify the share. We don't need the result.
        let _ = secret_share.verify()?;

        // Round 2, Step 3
        //
        // > Each P_i calculates their long-lived private signing share by computing
        // > s_i = ∑^n_{ℓ=1} f_ℓ(i), stores s_i securely, and deletes each f_ℓ(i).
        signing_share = signing_share + f_ell_i.to_scalar();
    }

    signing_share = signing_share + round2_secret_package.secret_share;

    // Build new signing share
    let old_signing_share = old_key_package.signing_share.to_scalar();
    signing_share = signing_share + old_signing_share;
    let signing_share = SigningShare::new(signing_share);

    // Round 2, Step 4
    //
    // > Each P_i calculates their public verification share Y_i = g^{s_i}.
    let verifying_share = signing_share.into();

    let commitments: BTreeMap<_, _> = new_round_1_packages
        .iter()
        .map(|(id, package)| (*id, &package.commitment))
        .chain(iter::once((
            round2_secret_package.identifier,
            &round2_secret_package.commitment,
        )))
        .collect();

    let zero_shares_public_key_package = PublicKeyPackage::from_dkg_commitments(&commitments)?;

    let mut new_verifying_shares = BTreeMap::new();

    for (identifier, verifying_share) in zero_shares_public_key_package.verifying_shares {
        let new_verifying_share = verifying_share.to_element()
            + old_pub_key_package
                .verifying_shares
                .get(&identifier)
                .ok_or(Error::UnknownIdentifier)?
                .to_element();
        new_verifying_shares.insert(identifier, VerifyingShare::new(new_verifying_share));
    }

    let public_key_package = PublicKeyPackage {
        header: old_pub_key_package.header,
        verifying_shares: new_verifying_shares,
        verifying_key: old_pub_key_package.verifying_key,
    };

    let key_package = KeyPackage {
        header: Header::default(),
        identifier: round2_secret_package.identifier,
        signing_share,
        verifying_share,
        verifying_key: public_key_package.verifying_key,
        min_signers: round2_secret_package.min_signers,
    };

    Ok((key_package, public_key_package))
}
