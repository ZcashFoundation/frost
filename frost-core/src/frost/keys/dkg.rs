//! Distributed Key Generation functions and structures.
//!
//! The DKG module supports generating FROST key shares in a distributed manner,
//! without a trusted dealer.
//!
//! For more details and an example, see the ciphersuite-specific crates, e.g.
//! [`frost_ristretto255::keys::dkg`](../../../../frost_ristretto255/keys/dkg).

use std::{collections::HashMap, iter};

use rand_core::{CryptoRng, RngCore};

use crate::{
    frost::Identifier, Challenge, Ciphersuite, Element, Error, Field, Group, Scalar, Signature,
    VerifyingKey,
};

use super::{
    evaluate_polynomial, evaluate_vss, generate_coefficients, generate_secret_polynomial,
    KeyPackage, PublicKeyPackage, SecretShare, SharedSecret, SigningShare,
    VerifiableSecretSharingCommitment, VerifyingShare,
};

/// DKG Round 1 structures.
pub mod round1 {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// The package that must be broadcast by each participant to all other participants
    /// between the first and second parts of the DKG protocol (round 1).
    #[derive(Clone, Deserialize, Serialize)]
    pub struct Package<C: Ciphersuite> {
        /// The identifier of the participant who is sending the package (i).
        pub sender_identifier: Identifier<C>,
        /// The public commitment from the participant (C_i)
        pub commitment: VerifiableSecretSharingCommitment<C>,
        /// The proof of knowledge of the temporary secret (σ_i = (R_i, μ_i))
        pub proof_of_knowledge: Signature<C>,
    }

    /// The secret package that must be kept in memory by the participant
    /// between the first and second parts of the DKG protocol (round 1).
    ///
    /// # Security
    ///
    /// This package MUST NOT be sent to other participants!
    #[derive(Clone)]
    pub struct SecretPackage<C: Ciphersuite> {
        /// The identifier of the participant holding the secret.
        pub identifier: Identifier<C>,
        /// Coefficients of the temporary secret polynomial for the participant.
        /// These are (a_{i0}, ..., a_{i(t−1)})) which define the polynomial f_i(x)
        pub coefficients: Vec<Scalar<C>>,
        /// The public commitment for the participant (C_i)
        pub commitment: VerifiableSecretSharingCommitment<C>,
        /// The total number of signers.
        pub max_signers: u16,
    }
}

/// DKG Round 2 structures.
pub mod round2 {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// A package that must be sent by each participant to some other participants
    /// in Round 2 of the DKG protocol. Note that there is one specific package
    /// for each specific recipient, in contrast to Round 1.
    ///
    /// # Security
    ///
    /// The package must be sent on an *confidential* and *authenticated* channel.
    #[derive(Clone, Deserialize, Serialize)]
    pub struct Package<C: Ciphersuite> {
        /// The identifier of the participant that generated the package (i).
        pub sender_identifier: Identifier<C>,
        /// The identifier of the participant what will receive the package (ℓ).
        pub receiver_identifier: Identifier<C>,
        /// The secret share being sent.
        pub secret_share: SigningShare<C>,
    }

    /// The secret package that must be kept in memory by the participant
    /// between the second and third parts of the DKG protocol (round 2).
    ///
    /// # Security
    ///
    /// This package MUST NOT be sent to other participants!
    pub struct SecretPackage<C: Ciphersuite> {
        /// The identifier of the participant holding the secret.
        pub identifier: Identifier<C>,
        /// The public commitment from the participant (C_i)
        pub commitment: VerifiableSecretSharingCommitment<C>,
        /// The participant's own secret share (f_i(i)).
        pub secret_share: Scalar<C>,
        /// The total number of signers.
        pub max_signers: u16,
    }
}

/// Performs the first part of the distributed key generation protocol
/// for the given participant.
///
/// It returns the [`round1::SecretPackage`] that must be kept in memory
/// by the participant for the other steps, and the [`round1::Package`] that
/// must be sent to other participants.
pub fn part1<C: Ciphersuite, R: RngCore + CryptoRng>(
    identifier: Identifier<C>,
    max_signers: u16,
    min_signers: u16,
    mut rng: R,
) -> Result<(round1::SecretPackage<C>, round1::Package<C>), Error<C>> {
    let secret: SharedSecret<C> = SharedSecret::random(&mut rng);

    // Round 1, Step 1
    //
    // > Every participant P_i samples t random values (a_{i0}, ..., a_{i(t−1)}) ← Z_q
    //
    // Round 1, Step 3
    //
    // > Every participant P_i computes a public commitment
    // > C⃗_i = 〈φ_{i0}, ..., φ_{i(t−1)}〉, where φ_{ij} = g^{a_{ij}}, 0 ≤ j ≤ t − 1
    let coefficients = generate_coefficients::<C, R>(min_signers as usize - 1, &mut rng);
    let (coefficients, commitment) =
        generate_secret_polynomial(&secret, max_signers, min_signers, coefficients)?;

    // Round 1, Step 2
    //
    // > Every P_i computes a proof of knowledge to the corresponding secret
    // > a_{i0} by calculating σ_i = (R_i, μ_i), such that k ← Z_q, R_i = g^k,
    // > c_i = H(i, Φ, g^{a_{i0}} , R_i), μ_i = k + a_{i0} · c_i, with Φ being
    // > a context string to prevent replay attacks.

    let k = <<C::Group as Group>::Field>::random(&mut rng);
    let R_i = <C::Group>::generator() * k;
    let c_i = challenge::<C>(identifier, &R_i, &commitment.0[0].0).ok_or(Error::DKGNotSupported)?;
    let mu_i = k + coefficients[0] * c_i.0;

    let secret_package = round1::SecretPackage {
        identifier,
        coefficients,
        commitment: commitment.clone(),
        max_signers,
    };
    let package = round1::Package {
        sender_identifier: identifier,
        commitment,
        proof_of_knowledge: Signature { R: R_i, z: mu_i },
    };

    Ok((secret_package, package))
}

/// Generates the challenge for the proof of knowledge to a secret for the DKG.
fn challenge<C>(
    identifier: Identifier<C>,
    R: &Element<C>,
    verifying_key: &Element<C>,
) -> Option<Challenge<C>>
where
    C: Ciphersuite,
{
    let mut preimage = vec![];

    preimage.extend_from_slice(identifier.serialize().as_ref());
    preimage.extend_from_slice(<C::Group>::serialize(R).as_ref());
    preimage.extend_from_slice(<C::Group>::serialize(verifying_key).as_ref());

    Some(Challenge(C::HDKG(&preimage[..])?))
}

/// Performs the second part of the distributed key generation protocol
/// for the participant holding the given [`round1::SecretPackage`],
/// given the received [`round1::Package`]s received from the other participants.
///
/// It returns the [`round2::SecretPackage`] that must be kept in memory
/// by the participant for the final step, and the [`round2::Package`]s that
/// must be sent to other participants.
pub fn part2<C: Ciphersuite>(
    secret_package: round1::SecretPackage<C>,
    round1_packages: &[round1::Package<C>],
) -> Result<(round2::SecretPackage<C>, Vec<round2::Package<C>>), Error<C>> {
    if round1_packages.len() != (secret_package.max_signers - 1) as usize {
        return Err(Error::IncorrectNumberOfPackages);
    }

    let mut round2_packages = Vec::new();

    for round1_package in round1_packages {
        let ell = round1_package.sender_identifier;
        // Round 1, Step 5
        //
        // > Upon receiving C⃗_ℓ, σ_ℓ from participants 1 ≤ ℓ ≤ n, ℓ ≠ i, participant
        // > P_i verifies σ_ℓ = (R_ℓ, μ_ℓ), aborting on failure, by checking
        // > R_ℓ ? ≟ g^{μ_ℓ} · φ^{-c_ℓ}_{ℓ0}, where c_ℓ = H(ℓ, Φ, φ_{ℓ0}, R_ℓ).
        let R_ell = round1_package.proof_of_knowledge.R;
        let mu_ell = round1_package.proof_of_knowledge.z;
        let phi_ell0 = round1_package.commitment.0[0].0;
        let c_ell = challenge::<C>(ell, &R_ell, &phi_ell0).ok_or(Error::DKGNotSupported)?;

        if R_ell != <C::Group>::generator() * mu_ell - phi_ell0 * c_ell.0 {
            return Err(Error::InvalidProofOfKnowledge);
        }

        // Round 2, Step 1
        //
        // > Each P_i securely sends to each other participant P_ℓ a secret share (ℓ, f_i(ℓ)),
        // > deleting f_i and each share afterward except for (i, f_i(i)),
        // > which they keep for themselves.
        let value = evaluate_polynomial(ell, &secret_package.coefficients);

        round2_packages.push(round2::Package {
            sender_identifier: secret_package.identifier,
            receiver_identifier: ell,
            secret_share: SigningShare(value),
        });
    }
    let fii = evaluate_polynomial(secret_package.identifier, &secret_package.coefficients);
    Ok((
        round2::SecretPackage {
            identifier: secret_package.identifier,
            commitment: secret_package.commitment,
            secret_share: fii,
            max_signers: secret_package.max_signers,
        },
        round2_packages,
    ))
}

/// Computes the verifying keys of the other participants for the third step
/// of the DKG protocol.
fn compute_verifying_keys<C: Ciphersuite>(
    round2_packages: &[round2::Package<C>],
    round1_packages_map: HashMap<Identifier<C>, &round1::Package<C>>,
    round2_secret_package: &round2::SecretPackage<C>,
) -> Result<HashMap<Identifier<C>, VerifyingShare<C>>, Error<C>> {
    // Round 2, Step 4
    //
    // > Any participant can compute the public verification share of any other participant
    // > by calculating Y_i = ∏_{j=1}^n ∏_{k=0}^{t−1} φ_{jk}^{i^k mod q}.
    let mut others_verifying_keys = HashMap::new();

    // Note that in this loop, "i" refers to the other participant whose public verification share
    // we are computing, and not the current participant.
    for i in round2_packages.iter().map(|p| p.sender_identifier) {
        let mut y_i = <C::Group>::identity();

        // We need to iterate through all commitment vectors, including our own,
        // so chain it manually
        for commitments in round2_packages
            .iter()
            .map(|p| {
                // Get the commitment vector for this participant
                Ok::<&VerifiableSecretSharingCommitment<C>, Error<C>>(
                    &round1_packages_map
                        .get(&p.sender_identifier)
                        .ok_or(Error::PackageNotFound)?
                        .commitment,
                )
            })
            // Chain our own commitment vector
            .chain(iter::once(Ok(&round2_secret_package.commitment)))
        {
            y_i = y_i + evaluate_vss(commitments?, i);
        }
        let y_i = VerifyingShare(y_i);
        others_verifying_keys.insert(i, y_i);
    }
    Ok(others_verifying_keys)
}

/// Performs the third and final part of the distributed key generation protocol
/// for the participant holding the given [`round2::SecretPackage`],
/// given the received [`round1::Package`]s and [`round2::Package`]s received from
/// the other participants.
///
/// It returns the [`KeyPackage`] that has the long-lived key share for the
/// participant, and the [`PublicKeyPackage`]s that has public information
/// about all participants; both of which are required to compute FROST
/// signatures.
pub fn part3<C: Ciphersuite>(
    round2_secret_package: &round2::SecretPackage<C>,
    round1_packages: &[round1::Package<C>],
    round2_packages: &[round2::Package<C>],
) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), Error<C>> {
    if round1_packages.len() != (round2_secret_package.max_signers - 1) as usize {
        return Err(Error::IncorrectNumberOfPackages);
    }
    if round1_packages.len() != round2_packages.len() {
        return Err(Error::IncorrectNumberOfPackages);
    }

    let mut signing_share = <<C::Group as Group>::Field>::zero();
    let mut group_public = <C::Group>::identity();

    let round1_packages_map: HashMap<Identifier<C>, &round1::Package<C>> = round1_packages
        .iter()
        .map(|package| (package.sender_identifier, package))
        .collect();

    for round2_package in round2_packages {
        // Sanity check; was the package really meant to us?
        if round2_package.receiver_identifier != round2_secret_package.identifier {
            return Err(Error::IncorrectPackage);
        }

        // Round 2, Step 2
        //
        // > Each P_i verifies their shares by calculating:
        // > g^{f_ℓ(i)} ≟ ∏^{t−1}_{k=0} φ^{i^k mod q}_{ℓk}, aborting if the
        // > check fails.
        let ell = round2_package.sender_identifier;
        let f_ell_i = round2_package.secret_share;

        let commitment = &round1_packages_map
            .get(&ell)
            .ok_or(Error::PackageNotFound)?
            .commitment;

        // The verification is exactly the same as the regular SecretShare verification;
        // however the required components are in different places.
        // Build a temporary SecretShare so what we can call verify().
        let secret_share = SecretShare {
            identifier: round2_secret_package.identifier,
            value: f_ell_i,
            commitment: commitment.clone(),
        };

        // Verify the share. We don't need the result.
        let _ = secret_share.verify()?;

        // Round 2, Step 3
        //
        // > Each P_i calculates their long-lived private signing share by computing
        // > s_i = ∑^n_{ℓ=1} f_ℓ(i), stores s_i securely, and deletes each f_ℓ(i).
        signing_share = signing_share + f_ell_i.0;

        // Round 2, Step 4
        //
        // > Each P_i calculates [...] the group’s public key Y = ∏^n_{j=1} φ_{j0}.
        group_public = group_public + commitment.0[0].0;
    }

    signing_share = signing_share + round2_secret_package.secret_share;
    group_public = group_public + round2_secret_package.commitment.0[0].0;

    let signing_share = SigningShare(signing_share);
    // Round 2, Step 4
    //
    // > Each P_i calculates their public verification share Y_i = g^{s_i}.
    let verifying_key = signing_share.into();
    let group_public = VerifyingKey {
        element: group_public,
    };

    // Round 2, Step 4
    //
    // > Any participant can compute the public verification share of any other participant
    // > by calculating Y_i = ∏_{j=1}^n ∏_{k=0}^{t−1} φ_{jk}^{i^k mod q}.
    let mut all_verifying_keys =
        compute_verifying_keys(round2_packages, round1_packages_map, round2_secret_package)?;

    // Add the participant's own public verification share for consistency
    all_verifying_keys.insert(round2_secret_package.identifier, verifying_key);

    let key_package = KeyPackage {
        identifier: round2_secret_package.identifier,
        secret_share: signing_share,
        public: verifying_key,
        group_public,
    };
    let public_key_package = PublicKeyPackage {
        signer_pubkeys: all_verifying_keys,
        group_public,
    };

    Ok((key_package, public_key_package))
}
