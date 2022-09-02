//! Distributed Key Generation functions and structures.

use std::{collections::HashMap, iter};

use rand_core::{CryptoRng, RngCore};

use crate::{
    frost::Identifier, Challenge, Ciphersuite, Field, Group, Scalar, Signature, VerifyingKey,
};

use super::{
    evaluate_polynomial, CoefficientCommitment, KeyPackage, PublicKeyPackage, SigningShare,
    VerifiableSecretSharingCommitment, VerifyingShare,
};

/// The package that must be broadcast by each participant to all other participants
/// between the first and second parts of the DKG protocol (round 1).
#[derive(Clone)]
pub struct Round1Package<C: Ciphersuite> {
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
pub struct Round1SecretPackage<C: Ciphersuite> {
    /// The identifier of the participant holding the secret.
    pub identifier: Identifier<C>,
    /// Coefficients of the temporary secret polynomial for the participant.
    /// These are (a_{i0}, ..., a_{i(t−1)})) which define the polynomial f_i(x)
    pub coefficients: Vec<Scalar<C>>,
    /// The public commitment for the participant (C_i)
    pub commitment: VerifiableSecretSharingCommitment<C>,
    /// The total number of signers.
    pub num_signers: u8,
}

/// A package that must be sent by each participant to some other participants
/// in Round 2 of the DKG protocol. Note that there is one specific package
/// for each specific recipient, in contrast to Round 1.
///
/// # Security
///
/// The package must be sent on an *confidential* and *authenticated* channel.
#[derive(Clone)]
pub struct Round2Package<C: Ciphersuite> {
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
pub struct Round2SecretPackage<C: Ciphersuite> {
    /// The identifier of the participant holding the secret.
    pub identifier: Identifier<C>,
    /// The public commitment from the participant (C_i)
    pub commitment: VerifiableSecretSharingCommitment<C>,
    /// The participant's own secret share (f_i(i)).
    pub secret_share: Scalar<C>,
    /// The total number of signers.
    pub num_signers: u8,
}

/// Performs the first part of the distributed key generation protocol
/// for the given participant.
///
/// It returns the [`Round1SecretPackage`] that must be kept in memory
/// by the participant for the other steps, and the [`Round1Package`] that
/// must be sent to other participants.
pub fn keygen_part1<C: Ciphersuite, R: RngCore + CryptoRng>(
    identifier: Identifier<C>,
    num_signers: u8,
    threshold: u8,
    mut rng: R,
) -> Result<(Round1SecretPackage<C>, Round1Package<C>), &'static str> {
    // TODO: refactor with generate_secret_values?
    if threshold < 2 {
        return Err("Threshold cannot be less than 2");
    }

    if num_signers < 2 {
        return Err("Number of signers cannot be less than the minimum threshold 2");
    }

    if threshold > num_signers {
        return Err("Threshold cannot exceed num_signers");
    }

    let mut coefficients: Vec<Scalar<C>> = Vec::with_capacity(threshold as usize);

    let mut commitment: VerifiableSecretSharingCommitment<C> =
        VerifiableSecretSharingCommitment(Vec::with_capacity(threshold as usize));

    // Round 1, Step 1
    //
    // > Every participant P_i samples t random values (a_{i0}, ..., a_{i(t−1)})) ← Z_q
    for _ in 0..threshold {
        coefficients.push(<<C::Group as Group>::Field as Field>::random(&mut rng));
    }

    // Round 1, Step 3
    //
    // > Every participant P_i computes a public commitment
    // > C_i = 〈φ_{i0}, ..., φ_{i(t−1)}〉, where φ_{ij} = g^{a_{ij}}, 0 ≤ j ≤ t − 1
    for c in &coefficients {
        commitment
            .0
            .push(CoefficientCommitment(<C::Group as Group>::generator() * *c));
    }

    // Round 1, Step 2
    //
    // > Every P_i computes a proof of knowledge to the corresponding secret
    // > a_{i0} by calculating σ_i = (R_i, μ_i), such that k ← Z_q, R_i = g^k,
    // > c_i = H(i, Φ, g^{a_{i0}} , R_i), μ_i = k + a_{i0} · c_i, with Φ being
    // > a context string to prevent replay attacks.

    let k = <<C::Group as Group>::Field as Field>::random(&mut rng);
    let R_i = <C::Group as Group>::generator() * k;
    let c_i = challenge::<C>(identifier, &R_i, &commitment.0[0].0)
        .ok_or("DKG not supported by ciphersuite")?;
    let mu_i = k + coefficients[0] * c_i.0;

    let secret_package = Round1SecretPackage {
        identifier,
        coefficients,
        commitment: commitment.clone(),
        num_signers,
    };
    let package = Round1Package {
        sender_identifier: identifier,
        commitment,
        proof_of_knowledge: Signature { R: R_i, z: mu_i },
    };

    Ok((secret_package, package))
}

/// Generates the challenge for the proof of knowledge to a secret for the DKG.
fn challenge<C>(
    identifier: Identifier<C>,
    R: &<C::Group as Group>::Element,
    verifying_key: &<C::Group as Group>::Element,
) -> Option<Challenge<C>>
where
    C: Ciphersuite,
{
    let mut preimage = vec![];

    let i_scalar = identifier
        .to_scalar()
        .expect("this will never fail after identifier is defined as scalar");

    preimage
        .extend_from_slice(<<C::Group as Group>::Field as Field>::serialize(&i_scalar).as_ref());
    preimage.extend_from_slice(<C::Group as Group>::serialize(R).as_ref());
    preimage.extend_from_slice(<C::Group as Group>::serialize(verifying_key).as_ref());

    Some(Challenge(C::HDKG(&preimage[..])?))
}

/// Performs the second part of the distributed key generation protocol
/// for the participant holding the given [`Round1SecretPackage`],
/// given the received [`Round1Package`]s received from the other participants.
///
/// It returns the [`Round2SecretPackage`] that must be kept in memory
/// by the participant for the final step, and the [`Round2Package`]s that
/// must be sent to other participants.
pub fn keygen_part2<C: Ciphersuite>(
    secret_package: Round1SecretPackage<C>,
    round1_packages: &[Round1Package<C>],
) -> Result<(Round2SecretPackage<C>, Vec<Round2Package<C>>), &'static str> {
    if round1_packages.len() != (secret_package.num_signers - 1) as usize {
        return Err("incorrect number of packages");
    }

    let mut round2_packages = Vec::new();

    for round1_package in round1_packages {
        let ell = round1_package.sender_identifier;
        // Round 1, Step 5
        //
        // > Upon receiving C_ℓ, σ_ℓ from participants 1 ≤ ℓ ≤ n, ℓ ≠ i, participant
        // > P_i verifies σ_ℓ = (R_ℓ, μ_ℓ), aborting on failure, by checking
        // > R_ℓ ? ≟ g^{μ_ℓ} · φ^{-c_ℓ}_{ℓ0}, where c_ℓ = H(ℓ, Φ, φ_{ℓ0}, R_ℓ).
        let R_ell = round1_package.proof_of_knowledge.R;
        let mu_ell = round1_package.proof_of_knowledge.z;
        let phi_ell0 = round1_package.commitment.0[0].0;
        let c_ell =
            challenge::<C>(ell, &R_ell, &phi_ell0).ok_or("DKG not supported by ciphersuite")?;

        if R_ell != <C::Group as Group>::generator() * mu_ell - phi_ell0 * c_ell.0 {
            return Err("Invalid proof of knowledge");
        }

        // Round 2, Step 1
        //
        // > Each P_i securely sends to each other participant P_ℓ a secret share (ℓ, f_i(ℓ)),
        // > deleting f_i and each share afterward except for (i, f_i(i)),
        // > which they keep for themselves.
        let value = evaluate_polynomial(
            ell,
            secret_package.coefficients[0],
            &secret_package.coefficients[1..],
        )?;

        round2_packages.push(Round2Package {
            sender_identifier: secret_package.identifier,
            receiver_identifier: ell,
            secret_share: SigningShare(value),
        });
    }
    let fii = evaluate_polynomial(
        secret_package.identifier,
        secret_package.coefficients[0],
        &secret_package.coefficients[1..],
    )?;
    Ok((
        Round2SecretPackage {
            identifier: secret_package.identifier,
            commitment: secret_package.commitment,
            secret_share: fii,
            num_signers: secret_package.num_signers,
        },
        round2_packages,
    ))
}

/// Performs the third and final part of the distributed key generation protocol
/// for the participant holding the given [`Round2SecretPackage`],
/// given the received [`Round1Package`]s and [`Round2Package`]s received from
/// the other participants.
///
/// It returns the [`KeyPackage`] that has the long-lived key share for the
/// participant, and the [`PublicKeyPackage`]s that has public information
/// about other participants; both of which are required to compute FROST
/// signatures.
pub fn keygen_part3<C: Ciphersuite>(
    round2_secret_package: &Round2SecretPackage<C>,
    round1_packages: &[Round1Package<C>],
    round2_packages: &[Round2Package<C>],
) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), &'static str> {
    if round1_packages.len() != (round2_secret_package.num_signers - 1) as usize {
        return Err("incorrect number of packages");
    }
    if round1_packages.len() != round2_packages.len() {
        return Err("inconsistent number of packages");
    }

    let mut signing_share: Scalar<C> = <<C::Group as Group>::Field as Field>::zero();
    let mut group_public: <C::Group as Group>::Element = <C::Group as Group>::identity();

    let round1_packages_map: HashMap<Identifier<C>, &Round1Package<C>> = round1_packages
        .iter()
        .map(|package| (package.sender_identifier, package))
        .collect();

    for round2_package in round2_packages {
        // Sanity check; was the package really meant to us?
        if round2_package.receiver_identifier != round2_secret_package.identifier {
            return Err("Round 2 package receiver is not the current participant");
        }

        // Round 2, Step 2
        //
        // > Each P_i verifies their shares by calculating:
        // > g^{f_ℓ(i)} ≟ ∏^{t−1}_{k=0} φ^{i^k mod q}_{ℓk}, aborting if the
        // > check fails.
        let ell = round2_package.sender_identifier;
        let f_ell_i = round2_package.secret_share;

        // TODO: refactor with SecretShare::verify()

        let f_result = <C::Group as Group>::generator() * f_ell_i.0;

        let i = round2_secret_package.identifier.to_scalar()?;

        let commitments = &round1_packages_map
            .get(&ell)
            .ok_or("commitment package missing")?
            .commitment;

        let (_, result) = commitments.0.iter().fold(
            (
                <<C::Group as Group>::Field as Field>::one(),
                <C::Group as Group>::identity(),
            ),
            |(i_to_the_k, sum_so_far), comm_k| (i * i_to_the_k, sum_so_far + comm_k.0 * i_to_the_k),
        );

        if !(f_result == result) {
            return Err("SecretShare is invalid.");
        }

        // Round 2, Step 3
        //
        // > Each P_i calculates their long-lived private signing share by computing
        // > s_i = ∑^n_{ℓ=1} f_ℓ(i), stores s_i securely, and deletes each f_ℓ(i).
        signing_share = signing_share + f_ell_i.0;

        // Round 2, Step 4
        //
        // > Each P_i calculates [...] the group’s public key Y = ∏^n_{j=1} φ_{j0}.
        group_public = group_public + commitments.0[0].0;
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
    // Any participant can compute the public verification share of any other participant
    // by calculating Y_i = ∏_{j=1}^n ∏_{k=0}^{t−1} φ_{jk}^{i^k mod q}.

    let mut others_verifying_keys = HashMap::new();

    // Note that in this loop, "i" refers to the other participant whose public verification share
    // we are computing, and not the current participant.
    for i_identifier in round2_packages.iter().map(|p| p.sender_identifier) {
        let i = i_identifier.to_scalar()?;
        let mut y_i = <C::Group as Group>::identity();

        for commitments in round2_packages
            .iter()
            .map(|p| {
                Ok::<&VerifiableSecretSharingCommitment<C>, &'static str>(
                    &round1_packages_map
                        .get(&p.sender_identifier)
                        .ok_or("Round 1 package not found for Round 2 participant")?
                        .commitment,
                )
            })
            .chain(iter::once(Ok(&round2_secret_package.commitment)))
        {
            let (_, result) = commitments?.0.iter().fold(
                (
                    <<C::Group as Group>::Field as Field>::one(),
                    <C::Group as Group>::identity(),
                ),
                |(i_to_the_k, sum_so_far), comm_k| {
                    (i * i_to_the_k, sum_so_far + comm_k.0 * i_to_the_k)
                },
            );
            y_i = y_i + result;
        }
        let y_i = VerifyingShare(y_i);
        others_verifying_keys.insert(i_identifier, y_i);
    }

    let key_package = KeyPackage {
        identifier: round2_secret_package.identifier,
        secret_share: signing_share,
        public: verifying_key,
        group_public,
    };
    let public_key_package = PublicKeyPackage {
        signer_pubkeys: others_verifying_keys,
        group_public,
    };

    Ok((key_package, public_key_package))
}
