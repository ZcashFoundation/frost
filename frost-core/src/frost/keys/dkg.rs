//! Distributed Key Generation functions and structures.
//!
//! The DKG module supports generating FROST key shares in a distributed manner,
//! without a trusted dealer, via two rounds of communication between all
//! participants.
//!
//! This implements FROST KeyGen from the original [FROST paper], specifically
//! Figure 1. This protocol is a variant of [Pedersen's DKG] that additionally
//! requires each participant to demonstrate knowledge of their secret by providing
//! other participants with proof in zero knowledge, instantiated as a Schnorr signature,
//! to protect against rogue-key attacks in the setting where `t ≥ n/2`.
//!
//! In Pedersen's DKG, each of the `n` participants executes [Feldman's
//! Verifiable Secret Sharing (VSS)][Feldman's VSS] as the dealer in parallel,
//! and derives their secret share as the sum of the shares received from each
//! of the `n` VSS executions.
//!
//! As required for any multi-party protocol using Feldman's VSS, the key
//! generation stage in FROST requires participants to maintain a consistent
//! view of the pubic commitments to the secret polynomial coefficients. This
//! DKG protocol requires participants to broadcast the commitment values
//! honestly (e.g., participants do not provide different commitment values to a
//! subset of participants) over a _[secure broadcast channel]_.
//!
//! For more details and an example, see the ciphersuite-specific crates, e.g.
//! [`frost_ristretto255::keys::dkg`](../../../../frost_ristretto255/keys/dkg).
//!
//! [FROST paper]: https://eprint.iacr.org/2020/852.pdf
//! [Pedersen's DKG]: https://link.springer.com/chapter/10.1007/3-540-46416-6_47
//! [Feldman's VSS]: https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf
//! [secure broadcast channel]: https://frost.zfnd.org/terminology.html#broadcast-channel

use std::{collections::HashMap, iter};

use rand_core::{CryptoRng, RngCore};

use crate::{
    frost::Identifier, Challenge, Ciphersuite, Element, Error, Field, Group, Scalar, Signature,
    SigningKey, VerifyingKey,
};

use super::{
    evaluate_polynomial, evaluate_vss, generate_coefficients, generate_secret_polynomial,
    validate_num_of_signers, KeyPackage, PublicKeyPackage, SecretShare, SigningShare,
    VerifiableSecretSharingCommitment, VerifyingShare,
};

/// DKG Round 1 structures.
pub mod round1 {
    use derive_getters::Getters;
    use zeroize::Zeroize;

    use super::*;

    /// The package that must be broadcast by each participant to all other participants
    /// between the first and second parts of the DKG protocol (round 1).
    #[derive(Clone, Debug, PartialEq, Eq, Getters)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
    pub struct Package<C: Ciphersuite> {
        /// The public commitment from the participant (C_i)
        pub(crate) commitment: VerifiableSecretSharingCommitment<C>,
        /// The proof of knowledge of the temporary secret (σ_i = (R_i, μ_i))
        pub(crate) proof_of_knowledge: Signature<C>,
        /// Ciphersuite ID for serialization
        #[cfg_attr(
            feature = "serde",
            serde(serialize_with = "crate::ciphersuite_serialize::<_, C>")
        )]
        #[cfg_attr(
            feature = "serde",
            serde(deserialize_with = "crate::ciphersuite_deserialize::<_, C>")
        )]
        #[getter(skip)]
        pub(super) ciphersuite: (),
    }

    impl<C> Package<C>
    where
        C: Ciphersuite,
    {
        /// Create a new [`Package`] instance.
        pub fn new(
            commitment: VerifiableSecretSharingCommitment<C>,
            proof_of_knowledge: Signature<C>,
        ) -> Self {
            Self {
                commitment,
                proof_of_knowledge,
                ciphersuite: (),
            }
        }
    }

    /// The secret package that must be kept in memory by the participant
    /// between the first and second parts of the DKG protocol (round 1).
    ///
    /// # Security
    ///
    /// This package MUST NOT be sent to other participants!
    #[derive(Clone, PartialEq, Eq)]
    pub struct SecretPackage<C: Ciphersuite> {
        /// The identifier of the participant holding the secret.
        pub(crate) identifier: Identifier<C>,
        /// Coefficients of the temporary secret polynomial for the participant.
        /// These are (a_{i0}, ..., a_{i(t−1)})) which define the polynomial f_i(x)
        pub(crate) coefficients: Vec<Scalar<C>>,
        /// The public commitment for the participant (C_i)
        pub(crate) commitment: VerifiableSecretSharingCommitment<C>,
        /// The total number of signers.
        pub(crate) max_signers: u16,
    }

    impl<C> std::fmt::Debug for SecretPackage<C>
    where
        C: Ciphersuite,
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SecretPackage")
                .field("identifier", &self.identifier)
                .field("coefficients", &"<redacted>")
                .field("commitment", &self.commitment)
                .field("max_signers", &self.max_signers)
                .finish()
        }
    }

    impl<C> Zeroize for SecretPackage<C>
    where
        C: Ciphersuite,
    {
        fn zeroize(&mut self) {
            for i in 0..self.coefficients.len() {
                self.coefficients[i] = <<C::Group as Group>::Field>::zero();
            }
        }
    }
}

/// DKG Round 2 structures.
pub mod round2 {
    use derive_getters::Getters;
    use zeroize::Zeroize;

    use super::*;

    /// A package that must be sent by each participant to some other participants
    /// in Round 2 of the DKG protocol. Note that there is one specific package
    /// for each specific recipient, in contrast to Round 1.
    ///
    /// # Security
    ///
    /// The package must be sent on an *confidential* and *authenticated* channel.
    #[derive(Clone, Debug, PartialEq, Eq, Getters)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
    pub struct Package<C: Ciphersuite> {
        /// The secret share being sent.
        pub(crate) secret_share: SigningShare<C>,
        /// Ciphersuite ID for serialization
        #[cfg_attr(
            feature = "serde",
            serde(serialize_with = "crate::ciphersuite_serialize::<_, C>")
        )]
        #[cfg_attr(
            feature = "serde",
            serde(deserialize_with = "crate::ciphersuite_deserialize::<_, C>")
        )]
        #[getter(skip)]
        pub(super) ciphersuite: (),
    }

    impl<C> Package<C>
    where
        C: Ciphersuite,
    {
        /// Create a new [`Package`] instance.
        pub fn new(secret_share: SigningShare<C>) -> Self {
            Self {
                secret_share,
                ciphersuite: (),
            }
        }
    }

    /// The secret package that must be kept in memory by the participant
    /// between the second and third parts of the DKG protocol (round 2).
    ///
    /// # Security
    ///
    /// This package MUST NOT be sent to other participants!
    #[derive(Clone, PartialEq, Eq)]
    pub struct SecretPackage<C: Ciphersuite> {
        /// The identifier of the participant holding the secret.
        pub(crate) identifier: Identifier<C>,
        /// The public commitment from the participant (C_i)
        pub(crate) commitment: VerifiableSecretSharingCommitment<C>,
        /// The participant's own secret share (f_i(i)).
        pub(crate) secret_share: Scalar<C>,
        /// The total number of signers.
        pub(crate) max_signers: u16,
    }

    impl<C> std::fmt::Debug for SecretPackage<C>
    where
        C: Ciphersuite,
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SecretPackage")
                .field("identifier", &self.identifier)
                .field("commitment", &self.commitment)
                .field("secret_share", &"<redacted>")
                .field("max_signers", &self.max_signers)
                .finish()
        }
    }

    impl<C> Zeroize for SecretPackage<C>
    where
        C: Ciphersuite,
    {
        fn zeroize(&mut self) {
            self.secret_share = <<C::Group as Group>::Field>::zero();
        }
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
    validate_num_of_signers::<C>(min_signers, max_signers)?;

    let secret: SigningKey<C> = SigningKey::new(&mut rng);

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
        commitment,
        proof_of_knowledge: Signature { R: R_i, z: mu_i },
        ciphersuite: (),
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
/// `round1_packages` maps the identifier of each participant to the
/// [`round1::Package`] they sent. These identifiers must come from whatever mapping
/// the coordinator has between communication channels and participants, i.e.
/// they must have assurance that the [`round1::Package`] came from
/// the participant with that identifier.
///
/// It returns the [`round2::SecretPackage`] that must be kept in memory
/// by the participant for the final step, and the a map of [`round2::Package`]s that
/// must be sent to each participant who has the given identifier in the map key.
pub fn part2<C: Ciphersuite>(
    secret_package: round1::SecretPackage<C>,
    round1_packages: &HashMap<Identifier<C>, round1::Package<C>>,
) -> Result<
    (
        round2::SecretPackage<C>,
        HashMap<Identifier<C>, round2::Package<C>>,
    ),
    Error<C>,
> {
    if round1_packages.len() != (secret_package.max_signers - 1) as usize {
        return Err(Error::IncorrectNumberOfPackages);
    }

    let mut round2_packages = HashMap::new();

    for (sender_identifier, round1_package) in round1_packages {
        let ell = *sender_identifier;
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
            return Err(Error::InvalidProofOfKnowledge { culprit: ell });
        }

        // Round 2, Step 1
        //
        // > Each P_i securely sends to each other participant P_ℓ a secret share (ℓ, f_i(ℓ)),
        // > deleting f_i and each share afterward except for (i, f_i(i)),
        // > which they keep for themselves.
        let value = evaluate_polynomial(ell, &secret_package.coefficients);

        round2_packages.insert(
            ell,
            round2::Package {
                secret_share: SigningShare(value),
                ciphersuite: (),
            },
        );
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
    round1_packages: &HashMap<Identifier<C>, round1::Package<C>>,
    round2_secret_package: &round2::SecretPackage<C>,
) -> Result<HashMap<Identifier<C>, VerifyingShare<C>>, Error<C>> {
    // Round 2, Step 4
    //
    // > Any participant can compute the public verification share of any other participant
    // > by calculating Y_i = ∏_{j=1}^n ∏_{k=0}^{t−1} φ_{jk}^{i^k mod q}.
    let mut others_verifying_keys = HashMap::new();

    // Note that in this loop, "i" refers to the other participant whose public verification share
    // we are computing, and not the current participant.
    for i in round1_packages.keys().cloned() {
        let mut y_i = <C::Group>::identity();

        // We need to iterate through all commitment vectors, including our own,
        // so chain it manually
        for commitment in round1_packages
            .keys()
            .map(|k| {
                // Get the commitment vector for this participant
                Ok::<&VerifiableSecretSharingCommitment<C>, Error<C>>(
                    &round1_packages
                        .get(k)
                        .ok_or(Error::PackageNotFound)?
                        .commitment,
                )
            })
            // Chain our own commitment vector
            .chain(iter::once(Ok(&round2_secret_package.commitment)))
        {
            y_i = y_i + evaluate_vss(commitment?, i);
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
/// `round1_packages` must be the same used in [`part2()`].
///
/// `round2_packages` maps the identifier of each participant to the
/// [`round2::Package`] they sent. These identifiers must come from whatever mapping
/// the coordinator has between communication channels and participants, i.e.
/// they must have assurance that the [`round2::Package`] came from
/// the participant with that identifier.
///
/// It returns the [`KeyPackage`] that has the long-lived key share for the
/// participant, and the [`PublicKeyPackage`]s that has public information
/// about all participants; both of which are required to compute FROST
/// signatures.
pub fn part3<C: Ciphersuite>(
    round2_secret_package: &round2::SecretPackage<C>,
    round1_packages: &HashMap<Identifier<C>, round1::Package<C>>,
    round2_packages: &HashMap<Identifier<C>, round2::Package<C>>,
) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), Error<C>> {
    if round1_packages.len() != (round2_secret_package.max_signers - 1) as usize {
        return Err(Error::IncorrectNumberOfPackages);
    }
    if round1_packages.len() != round2_packages.len() {
        return Err(Error::IncorrectNumberOfPackages);
    }
    if round1_packages
        .keys()
        .any(|id| !round2_packages.contains_key(id))
    {
        return Err(Error::IncorrectPackage);
    }

    let mut signing_share = <<C::Group as Group>::Field>::zero();
    let mut group_public = <C::Group>::identity();

    for (sender_identifier, round2_package) in round2_packages {
        // Round 2, Step 2
        //
        // > Each P_i verifies their shares by calculating:
        // > g^{f_ℓ(i)} ≟ ∏^{t−1}_{k=0} φ^{i^k mod q}_{ℓk}, aborting if the
        // > check fails.
        let ell = *sender_identifier;
        let f_ell_i = round2_package.secret_share;

        let commitment = &round1_packages
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
            ciphersuite: (),
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
    let mut all_verifying_keys = compute_verifying_keys(round1_packages, round2_secret_package)?;

    // Add the participant's own public verification share for consistency
    all_verifying_keys.insert(round2_secret_package.identifier, verifying_key);

    let key_package = KeyPackage {
        identifier: round2_secret_package.identifier,
        secret_share: signing_share,
        public: verifying_key,
        group_public,
        ciphersuite: (),
    };
    let public_key_package = PublicKeyPackage {
        signer_pubkeys: all_verifying_keys,
        group_public,
        ciphersuite: (),
    };

    Ok((key_package, public_key_package))
}
