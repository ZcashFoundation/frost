//! COCKTAIL Distributed Key Generation functions and structures.
//!
//! COCKTAIL-DKG is a standalone distributed key generation protocol for
//! threshold signature schemes like FROST. It is an independent derivative of
//! [ChillDKG](https://github.com/BlockstreamResearch/bip-frost-dkg) designed to
//! work with any FROST ciphersuite.
//!
//! Unlike the basic FROST DKG (see [`super::dkg`]) (also known as "PedPop"),
//! COCKTAIL-DKG:
//!
//! - Encrypts secret shares using pairwise ECDH (no pre-established secure
//!   channels needed)
//! - Uses long-term static key pairs for participant authentication
//! - Includes a certification round (Round 3) to detect split-view attacks
//! - Supports share recovery from a transcript and the static secret key
//!
//! ## Protocol Overview
//!
//! 1. **Round 1 ([`part1`])**: Each participant generates their polynomial,
//!    ephemeral key, proof of possession, and encrypts shares for all other
//!    participants.
//!
//! 2. **Round 2 ([`part2`])**: The coordinator aggregates Round 1 messages and
//!    sends them to all participants. Each participant decrypts and verifies
//!    received shares, computes their final key share and signs the public
//!    transcript.
//!
//! 3. **Round 3 ([`part3`])**: The coordinator broadcasts all transcript
//!    signatures. Each participant verifies them and, if all are valid, outputs
//!    their [`KeyPackage`] and [`PublicKeyPackage`].
//!
//! ## Trait Requirement
//!
//! Ciphersuites must implement [`CocktailCiphersuite`] in addition to
//! [`Ciphersuite`] to use this module. The additional methods provide:
//! - A hash-to-scalar function for the COCKTAIL Schnorr signature scheme
//! - A combined H6 key derivation + AEAD key/nonce derivation function
//! - AEAD encrypt/decrypt operations

use alloc::{collections::BTreeMap, vec::Vec};

use rand_core::{CryptoRng, RngCore};

use crate::{
    Ciphersuite, Element, Error, Field, Group, Identifier, Scalar, Signature, SigningKey,
    VerifyingKey,
};

use super::{
    evaluate_polynomial, generate_coefficients, generate_secret_polynomial,
    validate_num_of_signers, KeyPackage, PublicKeyPackage, SecretShare, SigningShare,
    VerifiableSecretSharingCommitment,
};

/// Extension trait for ciphersuites that support the COCKTAIL-DKG protocol.
///
/// Implementors must provide:
/// - The H6 hash function for AEAD key/nonce derivation
/// - AEAD encrypt/decrypt operations
///
/// See the [COCKTAIL-DKG specification](https://c2sp.org/cocktail-dkg) for details.
pub trait CocktailCiphersuite: Ciphersuite {
    /// Hash-to-scalar function for the COCKTAIL Schnorr PoP scheme.
    fn HPOP(data: &[u8]) -> Scalar<Self>;

    /// Hash function H6 for AEAD key/nonce derivation.
    ///
    /// Defined in the COCKTAIL-DKG specification as:
    /// `H6(Se, Sd, E, Pi, Pj, context) = Hash(domain || Se || Sd || E || Pi || Pj || len(context) || context)`
    fn H6(
        shared_secret_ephem: &[u8],
        shared_secret_static: &[u8],
        ephemeral_pub: &[u8],
        sender_pub: &[u8],
        recipient_pub: &[u8],
        context: &[u8],
    ) -> Vec<u8>;

    /// The ciphersuite's base hash function, used for KDF purposes when the H6
    /// output is shorter than 56 bytes.
    ///
    /// Called as `HKDF(label || ikm)` where label is either
    /// `"COCKTAIL-derive-key"` or `"COCKTAIL-derive-nonce"` and ikm is the
    /// H6 output.
    fn HKDF(data: &[u8]) -> Vec<u8>;

    /// Encrypt a plaintext using an AEAD scheme.
    fn aead_encrypt(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8]) -> Vec<u8>;

    /// Decrypt a ciphertext using an AEAD scheme.
    fn aead_decrypt(
        key: &[u8; 32],
        nonce: &[u8; 24],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error<Self>>;

    /// Optionally derive or update the extension from the payloads received in Round 2.
    ///
    /// Called in [`part2`] after all shares have been decrypted, before the transcript
    /// is built. The `extension` argument is the value originally passed to [`part2`].
    /// `received_payloads` maps each sender's [`Identifier`] to their decrypted payload
    /// (empty `Vec` if the sender sent no payload).
    ///
    /// The return value replaces `extension` when building the transcript.
    ///
    /// The default implementation returns `extension` unchanged. Override this to
    /// derive the extension from the payloads, for example by computing a
    /// commitment over all payloads as recommended in the COCKTAIL-DKG spec:
    ///
    /// ```text
    /// ext = H(n || len(payload_1) || payload_1 || ... || len(payload_n) || payload_n)
    /// ```
    fn derive_extension(
        extension: &[u8],
        _received_payloads: &BTreeMap<Identifier<Self>, Vec<u8>>,
    ) -> Vec<u8> {
        extension.to_vec()
    }
}

/// Derives a 256-bit key and 192-bit nonce from an H6 output, following the
/// `DeriveKeyAndNonce` helper in the COCKTAIL-DKG specification.
///
/// - If the H6 output is at least 56 bytes: `key = output[..32]`, `nonce = output[32..56]`.
/// - Otherwise: `key = H_kdf("COCKTAIL-derive-key" || ikm)`, `nonce = H_kdf("COCKTAIL-derive-nonce" || ikm)[..24]`.
fn derive_key_and_nonce<C: CocktailCiphersuite>(
    h6: &[u8],
) -> Result<([u8; 32], [u8; 24]), Error<C>> {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    if let (Some(k), Some(n)) = (h6.get(..32), h6.get(32..56)) {
        key.copy_from_slice(k);
        nonce.copy_from_slice(n);
    } else {
        let mut key_input = b"COCKTAIL-derive-key".to_vec();
        key_input.extend_from_slice(h6);
        let key_hash = C::HKDF(&key_input);
        key.copy_from_slice(key_hash.get(..32).ok_or(Error::InvalidSignature)?);

        let mut nonce_input = b"COCKTAIL-derive-nonce".to_vec();
        nonce_input.extend_from_slice(h6);
        let nonce_hash = C::HKDF(&nonce_input);
        nonce.copy_from_slice(nonce_hash.get(..24).ok_or(Error::InvalidSignature)?);
    }
    Ok((key, nonce))
}


/// Build the PoP message: `context || serialize(C_i) || serialize(E_i)`.
fn pop_message<C: Ciphersuite>(
    commitment: &VerifiableSecretSharingCommitment<C>,
    ephemeral_pub: &Element<C>,
    context: &[u8],
) -> Result<Vec<u8>, Error<C>> {
    let mut msg = Vec::new();
    msg.extend_from_slice(context);
    msg.extend_from_slice(&commitment.serialize_whole()?);
    msg.extend_from_slice(&<C::Group>::serialize(ephemeral_pub)?.as_ref().to_vec());
    Ok(msg)
}

/// COCKTAIL deterministic Schnorr sign for Proof of Possession.
///
/// `k = H(sk || m)`, `R = k·B`, `c = H(R || pk || m)`, `z = k + c·sk`
fn pop_sign<C: CocktailCiphersuite>(
    sk: Scalar<C>,
    message: &[u8],
) -> Result<Signature<C>, Error<C>> {
    let sk_bytes = <<C::Group as Group>::Field as Field>::serialize(&sk);
    let mut nonce_input = sk_bytes.as_ref().to_vec();
    nonce_input.extend_from_slice(message);
    let k = C::HPOP(&nonce_input);

    let R = <C::Group>::generator() * k;
    let pk = <C::Group>::generator() * sk;

    let R_bytes = <C::Group>::serialize(&R)?.as_ref().to_vec();
    let pk_bytes = <C::Group>::serialize(&pk)?.as_ref().to_vec();
    let mut challenge_input = R_bytes;
    challenge_input.extend_from_slice(&pk_bytes);
    challenge_input.extend_from_slice(message);
    let c = C::HPOP(&challenge_input);

    let z = k + c * sk;
    Ok(Signature { R, z })
}

/// COCKTAIL deterministic Schnorr verify for Proof of Possession.
///
/// `c = H(R || pk || m)`, check `z·B == R + c·pk`
fn pop_verify<C: CocktailCiphersuite>(
    pk: Element<C>,
    sig: &Signature<C>,
    message: &[u8],
) -> Result<(), Error<C>> {
    let R_bytes = <C::Group>::serialize(&sig.R)?.as_ref().to_vec();
    let pk_bytes = <C::Group>::serialize(&pk)?.as_ref().to_vec();
    let mut challenge_input = R_bytes;
    challenge_input.extend_from_slice(&pk_bytes);
    challenge_input.extend_from_slice(message);
    let c = C::HPOP(&challenge_input);

    let lhs = <C::Group>::generator() * sig.z;
    let rhs = sig.R + pk * c;

    if lhs != rhs {
        Err(Error::InvalidSignature)
    } else {
        Ok(())
    }
}

/// Parsed representation of a COCKTAIL-DKG transcript.
struct ParsedTranscript<C: CocktailCiphersuite> {
    context: Vec<u8>,
    n: u16,
    t: u16,
    participants: BTreeMap<Identifier<C>, VerifyingKey<C>>,
    commitments: BTreeMap<Identifier<C>, VerifiableSecretSharingCommitment<C>>,
    ephemeral_pubs: BTreeMap<Identifier<C>, Element<C>>,
}

/// Parse a canonical transcript byte string into its constituent fields.
///
/// Identifiers are reconstructed as the standard 1-based sequence `1..=n`.
/// Returns `Err(Error::InvalidSignature)` if the bytes are malformed or truncated.
fn parse_transcript<C: CocktailCiphersuite>(bytes: &[u8]) -> Result<ParsedTranscript<C>, Error<C>> {
    let elem_size = <C::Group>::serialize(&<C::Group>::generator())
        .expect("generator serialization always succeeds")
        .as_ref()
        .len();
    let scalar_size =
        <<C::Group as Group>::Field>::serialize(&<<C::Group as Group>::Field>::zero())
            .as_ref()
            .len();
    let sig_size = elem_size + scalar_size;

    let mut pos = 0usize;

    // Returns `bytes[pos..pos+n]` and advances `pos`, or errors if out of bounds.
    let mut take = |n: usize| -> Option<&[u8]> {
        let end = pos.checked_add(n)?;
        let slice = bytes.get(pos..end)?;
        pos = end;
        Some(slice)
    };

    let ctx_len = u64::from_le_bytes(
        take(8)
            .ok_or(Error::InvalidSignature)?
            .try_into()
            .expect("slice is 8 bytes"),
    ) as usize;
    let context = take(ctx_len).ok_or(Error::InvalidSignature)?.to_vec();

    let n = u32::from_le_bytes(
        take(4)
            .ok_or(Error::InvalidSignature)?
            .try_into()
            .expect("slice is 4 bytes"),
    ) as u16;
    let t = u32::from_le_bytes(
        take(4)
            .ok_or(Error::InvalidSignature)?
            .try_into()
            .expect("slice is 4 bytes"),
    ) as u16;

    let identifiers: Vec<Identifier<C>> = (1..=n)
        .map(Identifier::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    let mut participants = BTreeMap::new();
    for &id in &identifiers {
        let pk = VerifyingKey::deserialize(take(elem_size).ok_or(Error::InvalidSignature)?)?;
        participants.insert(id, pk);
    }

    let commitment_size = t as usize * elem_size;
    let mut commitments = BTreeMap::new();
    for &id in &identifiers {
        let c = VerifiableSecretSharingCommitment::deserialize_whole(
            take(commitment_size).ok_or(Error::InvalidSignature)?,
        )?;
        commitments.insert(id, c);
    }

    // Parse PoPs to advance pos; they are not needed for recovery.
    for _ in 0..n {
        let _ = Signature::default_deserialize(take(sig_size).ok_or(Error::InvalidSignature)?)?;
    }

    let mut ephemeral_pubs = BTreeMap::new();
    for &id in &identifiers {
        let pk = VerifyingKey::deserialize(take(elem_size).ok_or(Error::InvalidSignature)?)?;
        ephemeral_pubs.insert(id, pk.to_element());
    }

    let ext_len = u64::from_le_bytes(
        take(8)
            .ok_or(Error::InvalidSignature)?
            .try_into()
            .expect("slice is 8 bytes"),
    ) as usize;
    take(ext_len).ok_or(Error::InvalidSignature)?; // extension (not needed for recovery)

    if pos != bytes.len() {
        return Err(Error::InvalidSignature);
    }

    Ok(ParsedTranscript {
        context,
        n,
        t,
        participants,
        commitments,
        ephemeral_pubs,
    })
}

/// Build the canonical public transcript `T` for Round 3 certification.
///
/// Structure (exact order from the specification):
/// 1. `len(context)` as little-endian u64
/// 2. `context`
/// 3. `n` as little-endian u32
/// 4. `t` as little-endian u32
/// 5. `P_j` for each participant in identifier-sorted order
/// 6. `C_j` (full VSS commitment) for each participant in identifier-sorted order
/// 7. `PoP_j` for each participant in identifier-sorted order
/// 8. `E_j` for each participant in identifier-sorted order
/// 9. `len(ext)` as little-endian u64
/// 10. `ext`
#[allow(clippy::too_many_arguments)]
fn build_transcript<C: CocktailCiphersuite>(
    context: &[u8],
    n: u16,
    t: u16,
    participants: &BTreeMap<Identifier<C>, VerifyingKey<C>>,
    commitments: &BTreeMap<Identifier<C>, VerifiableSecretSharingCommitment<C>>,
    pops: &BTreeMap<Identifier<C>, Signature<C>>,
    ephemeral_pubs: &BTreeMap<Identifier<C>, Element<C>>,
    extension: &[u8],
) -> Result<Vec<u8>, Error<C>> {
    let mut t_bytes = Vec::new();

    t_bytes.extend_from_slice(&(context.len() as u64).to_le_bytes());
    t_bytes.extend_from_slice(context);
    t_bytes.extend_from_slice(&(n as u32).to_le_bytes());
    t_bytes.extend_from_slice(&(t as u32).to_le_bytes());

    for pk in participants.values() {
        t_bytes.extend_from_slice(&pk.serialize()?);
    }
    for id in participants.keys() {
        let c = commitments.get(id).ok_or(Error::PackageNotFound)?;
        t_bytes.extend_from_slice(&c.serialize_whole()?);
    }
    for id in participants.keys() {
        let pop = pops.get(id).ok_or(Error::PackageNotFound)?;
        t_bytes.extend_from_slice(&pop.default_serialize()?);
    }
    for id in participants.keys() {
        let e = ephemeral_pubs.get(id).ok_or(Error::PackageNotFound)?;
        t_bytes.extend_from_slice(&<C::Group>::serialize(e)?.as_ref().to_vec());
    }

    t_bytes.extend_from_slice(&(extension.len() as u64).to_le_bytes());
    t_bytes.extend_from_slice(extension);

    Ok(t_bytes)
}

/// DKG Round 1 structures.
pub mod round1 {
    use alloc::{collections::BTreeMap, vec::Vec};
    use derive_getters::Getters;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use crate::{serialization::SerializableScalar, Element, Group, Identifier, Scalar};

    use crate::keys::cocktail_dkg::CocktailCiphersuite;
    use crate::keys::VerifiableSecretSharingCommitment;
    use crate::Signature;

    /// The secret package that must be kept in memory by the participant
    /// between the first and second parts of the COCKTAIL-DKG protocol.
    ///
    /// # Security
    ///
    /// This package MUST NOT be sent to other participants!
    #[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, Getters)]
    pub struct SecretPackage<C: CocktailCiphersuite> {
        /// The identifier of the participant.
        #[zeroize(skip)]
        pub(crate) identifier: Identifier<C>,
        /// The secret polynomial coefficients $(a_{i,0}, \ldots, a_{i,t-1})$.
        #[getter(skip)]
        pub(crate) coefficients: Vec<SerializableScalar<C>>,
        /// The public VSS commitment $C_i$.
        #[zeroize(skip)]
        pub(crate) commitment: VerifiableSecretSharingCommitment<C>,
        /// The ephemeral secret key $e_i$.
        #[getter(skip)]
        pub(crate) ephemeral_secret: SerializableScalar<C>,
        /// The ephemeral public key $E_i = e_i \cdot B$.
        #[zeroize(skip)]
        pub(crate) ephemeral_pub: Element<C>,
        /// The proof of possession $PoP_i$ (needed in part2 to build the transcript).
        #[zeroize(skip)]
        pub(crate) proof_of_possession: Signature<C>,
        /// The minimum number of signers.
        pub(crate) min_signers: u16,
        /// The total number of signers.
        pub(crate) max_signers: u16,
    }

    impl<C: CocktailCiphersuite> SecretPackage<C> {
        /// Create a new [`SecretPackage`].
        #[allow(clippy::too_many_arguments)]
        pub fn new(
            identifier: Identifier<C>,
            coefficients: Vec<Scalar<C>>,
            commitment: VerifiableSecretSharingCommitment<C>,
            ephemeral_secret: Scalar<C>,
            ephemeral_pub: Element<C>,
            proof_of_possession: Signature<C>,
            min_signers: u16,
            max_signers: u16,
        ) -> Self {
            Self {
                identifier,
                coefficients: coefficients.into_iter().map(SerializableScalar).collect(),
                commitment,
                ephemeral_secret: SerializableScalar(ephemeral_secret),
                ephemeral_pub,
                proof_of_possession,
                min_signers,
                max_signers,
            }
        }

        /// Returns the secret polynomial coefficients.
        #[cfg_attr(feature = "internals", visibility::make(pub))]
        pub(crate) fn coefficients(&self) -> Vec<Scalar<C>> {
            self.coefficients.iter().map(|s| s.0).collect()
        }
    }

    impl<C> core::fmt::Debug for SecretPackage<C>
    where
        C: CocktailCiphersuite,
    {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("SecretPackage")
                .field("identifier", &self.identifier)
                .field("coefficients", &"<redacted>")
                .field("commitment", &self.commitment)
                .field("ephemeral_secret", &"<redacted>")
                .field("min_signers", &self.min_signers)
                .field("max_signers", &self.max_signers)
                .finish()
        }
    }

    /// The package that must be broadcast by each participant to all other participants
    /// (via the coordinator) between Round 1 and Round 2.
    ///
    /// Contains the VSS commitment, proof of possession, ephemeral public key,
    /// and encrypted shares for all participants.
    #[derive(Clone, PartialEq, Eq, Getters)]
    pub struct Package<C: CocktailCiphersuite> {
        /// The participant's identifier.
        pub(crate) identifier: Identifier<C>,
        /// The public VSS commitment $C_i$.
        pub(crate) commitment: VerifiableSecretSharingCommitment<C>,
        /// The proof of possession $PoP_i$.
        pub(crate) proof_of_possession: Signature<C>,
        /// The ephemeral public key $E_i$.
        pub(crate) ephemeral_pub: Element<C>,
        /// Encrypted shares: `encrypted_shares[j]` = $c_{i,j}$ for each participant $j$.
        pub(crate) encrypted_shares: BTreeMap<Identifier<C>, Vec<u8>>,
    }

    impl<C: CocktailCiphersuite> Package<C> {
        /// Create a new [`Package`].
        pub fn new(
            identifier: Identifier<C>,
            commitment: VerifiableSecretSharingCommitment<C>,
            proof_of_possession: Signature<C>,
            ephemeral_pub: Element<C>,
            encrypted_shares: BTreeMap<Identifier<C>, Vec<u8>>,
        ) -> Self {
            Self {
                identifier,
                commitment,
                proof_of_possession,
                ephemeral_pub,
                encrypted_shares,
            }
        }
    }

    impl<C> core::fmt::Debug for Package<C>
    where
        C: CocktailCiphersuite,
    {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Package")
                .field("identifier", &self.identifier)
                .field("commitment", &self.commitment)
                .field("proof_of_possession", &self.proof_of_possession)
                .field(
                    "ephemeral_pub",
                    &<C::Group>::serialize(&self.ephemeral_pub)
                        .map(|s| hex::encode(s.as_ref()))
                        .unwrap_or_else(|_| "<invalid>".into()),
                )
                .field("encrypted_shares", &self.encrypted_shares)
                .finish()
        }
    }
}

/// DKG Round 2 structures.
pub mod round2 {
    use alloc::{collections::BTreeMap, vec::Vec};
    use derive_getters::Getters;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use crate::{serialization::SerializableScalar, Identifier, Scalar, VerifyingKey};

    use crate::keys::cocktail_dkg::CocktailCiphersuite;
    use crate::keys::{PublicKeyPackage, VerifiableSecretSharingCommitment};
    use crate::Signature;

    /// The secret package that must be kept in memory by the participant
    /// between Round 2 and Round 3 of the COCKTAIL-DKG protocol.
    ///
    /// # Security
    ///
    /// This package MUST NOT be sent to other participants!
    #[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, Getters)]
    pub struct SecretPackage<C: CocktailCiphersuite> {
        /// The identifier of the participant.
        #[zeroize(skip)]
        pub(crate) identifier: Identifier<C>,
        /// The participant's own VSS commitment $C_i$.
        #[zeroize(skip)]
        pub(crate) commitment: VerifiableSecretSharingCommitment<C>,
        /// The participant's final long-lived secret share $x_i$.
        #[getter(skip)]
        pub(crate) secret_share: SerializableScalar<C>,
        /// The minimum number of signers.
        pub(crate) min_signers: u16,
        /// The total number of signers.
        pub(crate) max_signers: u16,
        /// The canonical public transcript $T$, used for certificate verification in Round 3.
        #[zeroize(skip)]
        pub(crate) transcript: Vec<u8>,
        /// All participants' static public keys, used to verify transcript signatures.
        #[zeroize(skip)]
        pub(crate) participants: BTreeMap<Identifier<C>, VerifyingKey<C>>,
        /// The precomputed public key package (computed once all shares are verified).
        #[zeroize(skip)]
        pub(crate) public_key_package: PublicKeyPackage<C>,
    }

    impl<C: CocktailCiphersuite> SecretPackage<C> {
        /// Create a new [`SecretPackage`].
        #[allow(clippy::too_many_arguments)]
        pub fn new(
            identifier: Identifier<C>,
            commitment: VerifiableSecretSharingCommitment<C>,
            secret_share: Scalar<C>,
            min_signers: u16,
            max_signers: u16,
            transcript: Vec<u8>,
            participants: BTreeMap<Identifier<C>, VerifyingKey<C>>,
            public_key_package: PublicKeyPackage<C>,
        ) -> Self {
            Self {
                identifier,
                commitment,
                secret_share: SerializableScalar(secret_share),
                min_signers,
                max_signers,
                transcript,
                participants,
                public_key_package,
            }
        }

        /// Returns the secret share scalar.
        pub fn secret_share(&self) -> Scalar<C> {
            self.secret_share.0
        }
    }

    impl<C> core::fmt::Debug for SecretPackage<C>
    where
        C: CocktailCiphersuite,
    {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("SecretPackage")
                .field("identifier", &self.identifier)
                .field("commitment", &self.commitment)
                .field("secret_share", &"<redacted>")
                .field("min_signers", &self.min_signers)
                .field("max_signers", &self.max_signers)
                .finish()
        }
    }

    /// The package sent by each participant to the coordinator after Round 2.
    ///
    /// Contains the participant's signature over the public transcript, used in the
    /// CertEq certification phase to ensure all participants agree on the DKG outcome.
    #[derive(Clone, Debug, PartialEq, Eq, Getters)]
    pub struct Package<C: CocktailCiphersuite> {
        /// The participant's signature over the transcript $T$.
        pub(crate) transcript_signature: Signature<C>,
    }

    impl<C: CocktailCiphersuite> Package<C> {
        /// Create a new [`Package`].
        pub fn new(transcript_signature: Signature<C>) -> Self {
            Self {
                transcript_signature,
            }
        }
    }
}

/// Performs the first part of the COCKTAIL-DKG protocol for the given participant.
///
/// The participant generates:
/// - A secret polynomial $f_i(x)$ of degree $t-1$
/// - A VSS commitment $C_i = (C_{i,0}, \ldots, C_{i,t-1})$
/// - An ephemeral key pair $(e_i, E_i)$
/// - A proof of possession $PoP_i$ (sign `context || C_i || E_i` with $a_{i,0}$)
/// - Encrypted secret shares $c_{i,j}$ for every participant $j$ (including self)
///
/// # Parameters
///
/// - `identifier`: The calling participant's identifier. Must be a key in `participants`.
/// - `max_signers`: The total number of participants $n$.
/// - `min_signers`: The threshold $t$ (minimum signers required to produce a signature).
/// - `static_signing_key`: The participant's long-term static private key $d_i$.
/// - `participants`: All participants' static public keys $P_j$, keyed by identifier.
///   Must include the calling participant's own key and have exactly `max_signers` entries.
/// - `context`: A session-unique context string. It is **RECOMMENDED** to construct this as
///   `H("COCKTAIL-DKG-CONTEXT" || session_id || P_1 || ... || P_n)`.
/// - `payloads`: Optional application-defined payloads to encrypt alongside each share.
///   `payloads[j]` is encrypted together with the share for participant `j` as
///   `plaintext = s_{i,j} || payload_{i,j}`. Missing entries are treated as empty.
/// - `rng`: A cryptographically secure random number generator.
///
/// # Returns
///
/// A tuple of:
/// - [`round1::SecretPackage`]: kept secret by the participant until [`part2`].
/// - [`round1::Package`]: broadcast to all other participants via the coordinator.
#[allow(clippy::too_many_arguments)]
pub fn part1<C: CocktailCiphersuite, R: RngCore + CryptoRng>(
    identifier: Identifier<C>,
    max_signers: u16,
    min_signers: u16,
    static_privkey: &SigningKey<C>,
    participants: &BTreeMap<Identifier<C>, VerifyingKey<C>>,
    context: &[u8],
    payloads: &BTreeMap<Identifier<C>, Vec<u8>>,
    mut rng: R,
) -> Result<(round1::SecretPackage<C>, round1::Package<C>), Error<C>> {
    validate_num_of_signers::<C>(min_signers, max_signers)?;

    if participants.len() != max_signers as usize {
        return Err(Error::IncorrectNumberOfIdentifiers);
    }
    if !participants.contains_key(&identifier) {
        return Err(Error::UnknownIdentifier);
    }

    // Steps 1 & 3: Generate secret polynomial and VSS commitment
    let secret: SigningKey<C> = SigningKey::new(&mut rng);
    let coefficients = generate_coefficients::<C, R>(min_signers as usize - 1, &mut rng);
    let (coefficients, commitment) =
        generate_secret_polynomial(&secret, max_signers, min_signers, coefficients)?;

    // Step 3: Generate ephemeral key pair (e_i, E_i)
    let ephemeral_privkey = <<C::Group as Group>::Field>::random(&mut rng);
    let ephemeral_pubkey = <C::Group>::generator() * ephemeral_privkey;

    // Step 4: Compute proof of possession using COCKTAIL deterministic Schnorr.
    // Sign `context || C_i || E_i` using a_{i,0} as the signing key.
    // The nonce is derived deterministically as k = H(a_{i,0} || message).
    let a_i0 = *coefficients
        .first()
        .expect("coefficients has at least one element");
    let pop_msg = pop_message::<C>(&commitment, &ephemeral_pubkey, context)?;
    let proof_of_possession = pop_sign::<C>(a_i0, &pop_msg)?;

    // Step 5: Compute and encrypt shares for each participant (including self)
    let static_pubkey = VerifyingKey::from(static_privkey);
    let sender_pubkey_bytes = static_pubkey.serialize()?;
    let ephemeral_pubkey_bytes = <C::Group>::serialize(&ephemeral_pubkey)?.as_ref().to_vec();
    let d_i = static_privkey.to_scalar();

    let mut encrypted_shares = BTreeMap::new();
    for (recipient_id, recipient_pubkey) in participants.iter() {
        // s_{i,j} = f_i(j)
        let share = evaluate_polynomial(*recipient_id, &coefficients);

        // S^(e)_{i,j} = e_i * P_j  and  S^(d)_{i,j} = d_i * P_j
        let recipient_element = recipient_pubkey.to_element();
        let s_ephem = recipient_element * ephemeral_privkey;
        let s_static = recipient_element * d_i;

        let h6 = C::H6(
            &<C::Group>::serialize(&s_ephem)?.as_ref().to_vec(),
            &<C::Group>::serialize(&s_static)?.as_ref().to_vec(),
            &ephemeral_pubkey_bytes,
            &sender_pubkey_bytes,
            &recipient_pubkey.serialize()?,
            context,
        );
        let (key, nonce) = derive_key_and_nonce::<C>(&h6)?;

        // Plaintext = share bytes || optional application payload
        let share_bytes = <<C::Group as Group>::Field>::serialize(&share);
        let mut plaintext = share_bytes.as_ref().to_vec();
        if let Some(payload) = payloads.get(recipient_id) {
            plaintext.extend_from_slice(payload);
        }
        let ciphertext = C::aead_encrypt(&key, &nonce, &plaintext);
        encrypted_shares.insert(*recipient_id, ciphertext);
    }

    let secret_package = round1::SecretPackage::new(
        identifier,
        coefficients.clone(),
        commitment.clone(),
        ephemeral_privkey,
        ephemeral_pubkey,
        proof_of_possession,
        min_signers,
        max_signers,
    );
    let package = round1::Package::new(
        identifier,
        commitment,
        proof_of_possession,
        ephemeral_pubkey,
        encrypted_shares,
    );

    Ok((secret_package, package))
}

/// Performs part 2 of the COCKTAIL-DKG protocol.
///
/// The coordinator aggregates all [`round1::Package`]s and delivers them to each participant.
/// This function:
/// - Validates that every VSS commitment contains exactly `t` points
/// - Verifies every proof of possession
/// - Decrypts and verifies every received secret share
/// - Computes the final secret share $x_i = \sum_j s_{j,i}$
/// - Performs a self-consistency check ($x_i \cdot B = Y_i$)
/// - Computes the group public key and all verifying shares
/// - Signs the public transcript for the CertEq phase
///
/// # Parameters
///
/// - `secret_package`: The [`round1::SecretPackage`] from [`part1`].
/// - `round1_packages`: [`round1::Package`]s from all **other** participants (n-1 total).
///   Keyed by sender identifier.
/// - `static_signing_key`: The participant's long-term static private key $d_i$.
/// - `participants`: Same map of static public keys used in [`part1`].
/// - `context`: Same context string used in [`part1`].
/// - `extension`: Optional application-specific extension bytes (may be `&[]`).
///
/// # Returns
///
/// A tuple of:
/// - [`round2::SecretPackage`]: kept secret by the participant until [`part3`].
/// - [`round2::Package`]: the transcript signature, sent to the coordinator.
pub fn part2<C: CocktailCiphersuite, R: RngCore + CryptoRng>(
    secret_package: round1::SecretPackage<C>,
    round1_packages: &BTreeMap<Identifier<C>, round1::Package<C>>,
    static_signing_key: &SigningKey<C>,
    participants: &BTreeMap<Identifier<C>, VerifyingKey<C>>,
    context: &[u8],
    extension: &[u8],
    mut rng: R,
) -> Result<
    (
        round2::SecretPackage<C>,
        round2::Package<C>,
        BTreeMap<Identifier<C>, Vec<u8>>,
    ),
    Error<C>,
> {
    if round1_packages.len() != (secret_package.max_signers - 1) as usize {
        return Err(Error::IncorrectNumberOfPackages);
    }

    let my_id = secret_package.identifier;
    let d_i = static_signing_key.to_scalar();
    let my_static_pub = VerifyingKey::from(static_signing_key);
    let my_pub_bytes = my_static_pub.serialize()?;

    // Unpack our own coefficients and ephemeral secret
    let my_coefficients: Vec<Scalar<C>> = secret_package.coefficients();

    // Steps 1 & 2: Validate commitments and verify all proofs of possession
    for (sender_id, package) in round1_packages.iter() {
        if package.commitment.min_signers() != secret_package.min_signers {
            return Err(Error::IncorrectNumberOfCommitments);
        }
        let pop_msg = pop_message::<C>(&package.commitment, &package.ephemeral_pub, context)?;
        let pop_pubkey = package.commitment.verifying_key()?;
        pop_verify::<C>(
            pop_pubkey.to_element(),
            &package.proof_of_possession,
            &pop_msg,
        )
        .map_err(|_| Error::InvalidProofOfKnowledge {
            culprit: *sender_id,
        })?;
    }

    // Build complete maps for transcript construction
    let mut all_commitments: BTreeMap<Identifier<C>, VerifiableSecretSharingCommitment<C>> =
        BTreeMap::new();
    let mut all_pops: BTreeMap<Identifier<C>, Signature<C>> = BTreeMap::new();
    let mut all_ephemeral_pubs: BTreeMap<Identifier<C>, Element<C>> = BTreeMap::new();

    for (sender_id, package) in round1_packages.iter() {
        all_commitments.insert(*sender_id, package.commitment.clone());
        all_pops.insert(*sender_id, package.proof_of_possession);
        all_ephemeral_pubs.insert(*sender_id, package.ephemeral_pub);
    }
    // Add our own
    all_commitments.insert(my_id, secret_package.commitment.clone());
    all_ephemeral_pubs.insert(my_id, secret_package.ephemeral_pub);
    all_pops.insert(my_id, secret_package.proof_of_possession);

    // Step 3: Decrypt, verify, and accumulate all shares
    let mut signing_share_scalar = <<C::Group as Group>::Field>::zero();
    let mut received_payloads: BTreeMap<Identifier<C>, Vec<u8>> = BTreeMap::new();

    // Self-share: s_{i,i} = f_i(i)
    let self_share_val = evaluate_polynomial(my_id, &my_coefficients);
    SecretShare::new(
        my_id,
        SigningShare::new(self_share_val),
        secret_package.commitment.clone(),
    )
    .verify()
    .map_err(|e| match e {
        Error::InvalidSecretShare { .. } => Error::InvalidSecretShare {
            culprit: Some(my_id),
        },
        other => other,
    })?;
    signing_share_scalar = signing_share_scalar + self_share_val;

    for (sender_id, package) in round1_packages.iter() {
        let sender_pubkey = participants
            .get(sender_id)
            .ok_or(Error::UnknownIdentifier)?;

        // Recipient derives keys:
        // S^(e)_{j,i} = d_i * E_j  (our static key with sender's ephemeral)
        // S^(d)_{j,i} = d_i * P_j  (our static key with sender's static)
        let s_ephemeral = package.ephemeral_pub * d_i;
        let s_static = sender_pubkey.to_element() * d_i;

        let h6 = C::H6(
            &<C::Group>::serialize(&s_ephemeral)?.as_ref().to_vec(),
            &<C::Group>::serialize(&s_static)?.as_ref().to_vec(),
            &<C::Group>::serialize(&package.ephemeral_pub)?.as_ref().to_vec(),
            &sender_pubkey.serialize()?,
            &my_pub_bytes,
            context,
        );
        let (key, nonce) = derive_key_and_nonce::<C>(&h6)?;

        let ciphertext = package
            .encrypted_shares
            .get(&my_id)
            .ok_or(Error::PackageNotFound)?;

        let plaintext =
            C::aead_decrypt(&key, &nonce, ciphertext).map_err(|_| Error::DecryptionFailed {
                culprit: *sender_id,
            })?;

        // Parse: first scalar_len bytes are s_{j,i}; rest is optional payload
        let scalar_len =
            <<C::Group as Group>::Field>::serialize(&<<C::Group as Group>::Field>::zero())
                .as_ref()
                .len();

        if plaintext.len() < scalar_len {
            return Err(Error::DecryptionFailed {
                culprit: *sender_id,
            });
        }

        let share_bytes = plaintext.get(..scalar_len).ok_or(Error::DecryptionFailed {
            culprit: *sender_id,
        })?;
        let share_ser = <<<C::Group as Group>::Field as Field>::Serialization>::try_from(
            share_bytes,
        )
        .map_err(|_| Error::DecryptionFailed {
            culprit: *sender_id,
        })?;
        let s_j_i = <<C::Group as Group>::Field>::deserialize(&share_ser).map_err(|_| {
            Error::DecryptionFailed {
                culprit: *sender_id,
            }
        })?;

        // Collect optional payload (remainder after the share bytes)
        let payload = plaintext.get(scalar_len..).ok_or(Error::DecryptionFailed { culprit: *sender_id })?.to_vec();
        received_payloads.insert(*sender_id, payload);

        // Verify share against sender's VSS commitment
        SecretShare::new(my_id, SigningShare::new(s_j_i), package.commitment.clone())
            .verify()
            .map_err(|e| match e {
                Error::InvalidSecretShare { .. } => Error::InvalidSecretShare {
                    culprit: Some(*sender_id),
                },
                other => other,
            })?;

        signing_share_scalar = signing_share_scalar + s_j_i;
    }

    // Compute the public key package from all commitments
    let commitments_refs: BTreeMap<Identifier<C>, &VerifiableSecretSharingCommitment<C>> =
        all_commitments.iter().map(|(id, c)| (*id, c)).collect();
    let public_key_package = PublicKeyPackage::from_dkg_commitments(&commitments_refs)?;

    // Self-consistency check: x_i * B must equal Y_i
    // (Guaranteed by VSS verifications above; this is a defence-in-depth measure.)
    let my_verifying_share = public_key_package
        .verifying_shares()
        .get(&my_id)
        .ok_or(Error::UnknownIdentifier)?;
    if <C::Group>::generator() * signing_share_scalar != my_verifying_share.to_element() {
        return Err(Error::InvalidSecretShare { culprit: None });
    }

    // Allow the ciphersuite to derive or update the extension from received payloads
    let effective_extension = C::derive_extension(extension, &received_payloads);

    // Build transcript and sign it with d_i
    let transcript = build_transcript::<C>(
        context,
        secret_package.max_signers,
        secret_package.min_signers,
        participants,
        &all_commitments,
        &all_pops,
        &all_ephemeral_pubs,
        &effective_extension,
    )?;
    let transcript_signature = static_signing_key.sign(&mut rng, &transcript);

    let round2_secret = round2::SecretPackage::new(
        my_id,
        secret_package.commitment.clone(),
        signing_share_scalar,
        secret_package.min_signers,
        secret_package.max_signers,
        transcript,
        participants.clone(),
        public_key_package,
    );
    let round2_package = round2::Package::new(transcript_signature);

    Ok((round2_secret, round2_package, received_payloads))
}

/// Performs part 3 (CertEq) of the COCKTAIL-DKG protocol.
///
/// The coordinator broadcasts all transcript signatures from all participants.
/// This function verifies every signature $sig_j$ on the transcript $T$ against
/// each participant's static public key $P_j$.
///
/// If all signatures are valid, every honest participant has agreed on the same
/// public DKG state and the protocol is complete. The collection of all $n$
/// signatures on the transcript forms a "success certificate" that can be stored
/// for auditing or share recovery.
///
/// # Parameters
///
/// - `secret_package`: The [`round2::SecretPackage`] from [`part2`].
/// - `round2_packages`: [`round2::Package`]s from **all** participants (n total, including
///   the caller's own). Keyed by participant identifier.
///
/// # Returns
///
/// A tuple of:
/// - [`KeyPackage`]: the participant's long-lived signing key share.
/// - [`PublicKeyPackage`]: the group public key and all participants' verifying shares.
/// - `Vec<u8>`: the canonical transcript bytes `T`.  Together with the success certificate
///   this forms the recovery data that any participant can use to call [`recover`].
/// - [`BTreeMap`]`<`[`Identifier`]`, `[`Signature`]`>`: the success certificate — all `n`
///   participants' signatures on `T`, keyed by signer identifier.
#[allow(clippy::type_complexity)]
pub fn part3<C: CocktailCiphersuite>(
    secret_package: &round2::SecretPackage<C>,
    round2_packages: &BTreeMap<Identifier<C>, round2::Package<C>>,
) -> Result<
    (
        KeyPackage<C>,
        PublicKeyPackage<C>,
        Vec<u8>,
        BTreeMap<Identifier<C>, Signature<C>>,
    ),
    Error<C>,
> {
    if round2_packages.len() != secret_package.max_signers as usize {
        return Err(Error::IncorrectNumberOfPackages);
    }

    // Verify all n transcript signatures
    for (signer_id, package) in round2_packages.iter() {
        let signer_pubkey = secret_package
            .participants
            .get(signer_id)
            .ok_or(Error::UnknownIdentifier)?;

        signer_pubkey
            .verify(&secret_package.transcript, &package.transcript_signature)
            .map_err(|_| Error::InvalidTranscriptSignature {
                culprit: *signer_id,
            })?;
    }

    // Collect the success certificate
    let success_certificate: BTreeMap<Identifier<C>, Signature<C>> = round2_packages
        .iter()
        .map(|(&id, pkg)| (id, pkg.transcript_signature))
        .collect();

    // All signatures verified, output final keys
    let signing_share = SigningShare::new(secret_package.secret_share());
    let verifying_share = *secret_package
        .public_key_package
        .verifying_shares()
        .get(&secret_package.identifier)
        .ok_or(Error::UnknownIdentifier)?;
    let verifying_key = *secret_package.public_key_package.verifying_key();

    let key_package = KeyPackage::new(
        secret_package.identifier,
        signing_share,
        verifying_share,
        verifying_key,
        secret_package.min_signers,
    );

    let (key_package, public_key_package) =
        C::post_dkg(key_package, secret_package.public_key_package.clone())?;

    Ok((
        key_package,
        public_key_package,
        secret_package.transcript.clone(),
        success_certificate,
    ))
}

/// Recovers a participant's DKG outputs from the static secret key, transcript,
/// success certificate, and ciphertexts.
///
/// This implements the COCKTAIL-DKG share recovery algorithm from the specification.
/// It allows a participant to reconstruct their secret share and the group public key
/// after a successful DKG session, given only their static secret key and the
/// publicly-available recovery data.
///
/// # Parameters
///
/// - `static_signing_key`: The participant's long-term static private key $d_i$.
/// - `transcript`: The canonical transcript bytes $T$ from a successful DKG session,
///   as returned by [`part3`].
/// - `success_certificate`: All $n$ participants' signatures on $T$, as returned by
///   [`part3`].
/// - `ciphertexts`: The encrypted shares $c_{j,i}$ from each sender $j$ to the recovering
///   participant $i$. Keys are sender identifiers. These are the per-recipient ciphertexts
///   from each sender's [`round1::Package`].
///
/// # Returns
///
/// A tuple of:
/// - [`KeyPackage`]: the participant's long-lived signing key share.
/// - [`PublicKeyPackage`]: the group public key and all participants' verifying shares.
pub fn recover<C: CocktailCiphersuite>(
    static_signing_key: &SigningKey<C>,
    transcript: &[u8],
    success_certificate: &BTreeMap<Identifier<C>, Signature<C>>,
    ciphertexts: &BTreeMap<Identifier<C>, Vec<u8>>,
) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), Error<C>> {
    let parsed = parse_transcript::<C>(transcript)?;

    // Step 1: Validate the success certificate.
    if success_certificate.len() != parsed.n as usize {
        return Err(Error::IncorrectNumberOfPackages);
    }
    for (signer_id, sig) in success_certificate {
        let pk = parsed
            .participants
            .get(signer_id)
            .ok_or(Error::UnknownIdentifier)?;
        pk.verify(transcript, sig)
            .map_err(|_| Error::InvalidTranscriptSignature {
                culprit: *signer_id,
            })?;
    }

    // Step 3: Find our identifier by matching d_i * B against the participant list.
    let my_pub = VerifyingKey::from(static_signing_key);
    let my_id = parsed
        .participants
        .iter()
        .find(|(_, pk)| **pk == my_pub)
        .map(|(id, _)| *id)
        .ok_or(Error::UnknownIdentifier)?;

    let my_pub_bytes = my_pub.serialize()?;
    let d_i = static_signing_key.to_scalar();

    let scalar_len = <<C::Group as Group>::Field>::serialize(&<<C::Group as Group>::Field>::zero())
        .as_ref()
        .len();

    // Steps 4–7: For each sender j, derive decryption key, decrypt, verify, and accumulate.
    let mut signing_share_scalar = <<C::Group as Group>::Field>::zero();

    for (&sender_id, sender_pub) in &parsed.participants {
        let ephemeral_pub = parsed
            .ephemeral_pubs
            .get(&sender_id)
            .ok_or(Error::PackageNotFound)?;
        let ciphertext = ciphertexts.get(&sender_id).ok_or(Error::PackageNotFound)?;

        // S^(e)_{j,i} = d_i * E_j  and  S^(d)_{j,i} = d_i * P_j
        let s_ephem = *ephemeral_pub * d_i;
        let s_static = sender_pub.to_element() * d_i;

        let h6 = C::H6(
            &<C::Group>::serialize(&s_ephem)?.as_ref().to_vec(),
            &<C::Group>::serialize(&s_static)?.as_ref().to_vec(),
            &<C::Group>::serialize(ephemeral_pub)?.as_ref().to_vec(),
            &sender_pub.serialize()?,
            &my_pub_bytes,
            &parsed.context,
        );
        let (key, nonce) = derive_key_and_nonce::<C>(&h6)?;

        let plaintext = C::aead_decrypt(&key, &nonce, ciphertext)
            .map_err(|_| Error::DecryptionFailed { culprit: sender_id })?;

        if plaintext.len() < scalar_len {
            return Err(Error::DecryptionFailed { culprit: sender_id });
        }

        let share_ser = <<<C::Group as Group>::Field as Field>::Serialization>::try_from(
            plaintext.get(..scalar_len).ok_or(Error::DecryptionFailed { culprit: sender_id })?,
        )
        .map_err(|_| Error::DecryptionFailed { culprit: sender_id })?;
        let s_j_i = <<C::Group as Group>::Field>::deserialize(&share_ser)
            .map_err(|_| Error::DecryptionFailed { culprit: sender_id })?;

        // Verify the decrypted share against the sender's VSS commitment.
        let commitment = parsed
            .commitments
            .get(&sender_id)
            .ok_or(Error::PackageNotFound)?;
        SecretShare::new(my_id, SigningShare::new(s_j_i), commitment.clone())
            .verify()
            .map_err(|e| match e {
                Error::InvalidSecretShare { .. } => Error::InvalidSecretShare {
                    culprit: Some(sender_id),
                },
                other => other,
            })?;

        signing_share_scalar = signing_share_scalar + s_j_i;
    }

    // Step 8: Compute public outputs from all VSS commitments.
    let commitments_refs: BTreeMap<Identifier<C>, &VerifiableSecretSharingCommitment<C>> =
        parsed.commitments.iter().map(|(id, c)| (*id, c)).collect();
    let public_key_package = PublicKeyPackage::from_dkg_commitments(&commitments_refs)?;

    let signing_share = SigningShare::new(signing_share_scalar);
    let verifying_share = *public_key_package
        .verifying_shares()
        .get(&my_id)
        .ok_or(Error::UnknownIdentifier)?;
    let verifying_key = *public_key_package.verifying_key();

    let key_package = KeyPackage::new(
        my_id,
        signing_share,
        verifying_share,
        verifying_key,
        parsed.t,
    );

    C::post_dkg(key_package, public_key_package)
}
