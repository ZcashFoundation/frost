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
//! 1. **Part 1 ([`part1`])**: Each participant generates their polynomial,
//!    ephemeral key, proof of possession, and encrypts shares for all other
//!    participants. Participants can send the generate packages to the other
//!    participants directly, or via a "coordinator" which aggregates messages.
//!
//! 2. **Part 2 ([`part2`])**: Each participant decrypts and verifies received
//!    shares, computes their final key share and signs the public transcript.
//!    Again, participants can send their transcript signatures directly to each
//!    other, or via the coordinator.
//!
//! 3. **Part 3 ([`part3`])**: Each participant verifies the transcript
//!    signatures from all other participants and, if all are valid, outputs
//!    their [`KeyPackage`] and [`PublicKeyPackage`].
//!
//! ## Trait Requirement
//!
//! Ciphersuites must implement [`CocktailCiphersuite`] in addition to
//! [`Ciphersuite`] to use this module.
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use rand_core::{CryptoRng, RngCore};

use crate::{
    random_nonzero, Ciphersuite, Element, Error, Field, Group, Identifier, Scalar, Signature,
    SigningKey, VerifyingKey,
};

use super::{
    evaluate_polynomial, generate_secret_polynomial, validate_num_of_signers, KeyPackage,
    PublicKeyPackage, SecretShare, SigningShare, VerifiableSecretSharingCommitment,
};

/// Extension trait for ciphersuites that support the COCKTAIL-DKG protocol.
pub trait CocktailCiphersuite: Ciphersuite {
    /// The canonical `ciphersuite_id` string from the COCKTAIL-DKG
    /// specification, e.g. `COCKTAIL(Ristretto255, SHA-512)`.
    ///
    /// It is bound into the canonical transcript and (under the recommended
    /// construction) into the session `context`.
    const COCKTAIL_ID: &'static str;

    /// The output size of the [`H6`](Self::H6) hash function in bytes.
    ///
    /// If this is at least 56, the AEAD key and nonce are derived from a
    /// single `H6` output; otherwise two domain-separated `H6` invocations
    /// (with `derive_extra(context, "key")` and `derive_extra(context, "nonce")`
    /// as the `extra` input) are used.
    const H6_OUTPUT_SIZE: usize;

    /// The AEAD authentication tag size in bytes.
    const AEAD_TAG_SIZE: usize = 16;

    /// Nonce derivation for the COCKTAIL Schnorr scheme:
    /// `k = HashToScalar(prefix_nonce || secret_key || message)`, where
    /// `prefix_nonce` is the ciphersuite-specific nonce prefix (e.g.
    /// `COCKTAIL-DKG-Ristretto255-SHA512-NONCE`) and `HashToScalar` is the
    /// ciphersuite's Schnorr hash-to-scalar reduction.
    ///
    /// For secp256k1, this is the BIP-340 tagged hash with tag
    /// `COCKTAIL-DKG/NONCE` instead.
    fn HNONCE(secret_key: &[u8], message: &[u8]) -> Scalar<Self>;

    /// Challenge derivation for the COCKTAIL Schnorr scheme:
    /// `c = HashToScalar(prefix_H7 || R || pk || message)`, where `prefix_H7`
    /// is the ciphersuite-specific challenge prefix (e.g.
    /// `COCKTAIL-DKG-Ristretto255-SHA512-H7`).
    ///
    /// For secp256k1, this is the BIP-340 tagged hash with tag
    /// `COCKTAIL-DKG/H7` instead.
    fn H7(commitment: &[u8], public_key: &[u8], message: &[u8]) -> Scalar<Self>;

    /// Hash function H6 for AEAD key/nonce derivation.
    ///
    /// Defined in the COCKTAIL-DKG specification as:
    /// `H6(Se || Sd, E, Ps, Pr, extra) = Hash(prefix || Se || Sd || E || Ps || Pr || len(extra) || extra)`
    /// where `len(extra)` is a little-endian 64-bit integer. (The secp256k1
    /// ciphersuite instead uses a BIP-340 tagged hash and omits `len(extra)`.)
    fn H6(
        shared_secret_ephem: &[u8],
        shared_secret_static: &[u8],
        ephemeral_pub: &[u8],
        sender_pub: &[u8],
        recipient_pub: &[u8],
        extra: &[u8],
    ) -> Vec<u8>;

    /// Encrypt a plaintext using an AEAD scheme.
    fn aead_encrypt(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8]) -> Vec<u8>;

    /// Decrypt a ciphertext using an AEAD scheme.
    fn aead_decrypt(
        key: &[u8; 32],
        nonce: &[u8; 24],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error<Self>>;

    /// The size in bytes of the COCKTAIL scalar encoding for this ciphersuite.
    ///
    /// Defaults to the size of the ciphersuite's scalar field encoding.
    /// Ed448 overrides this to 56 (bare little-endian scalars without the
    /// trailing zero byte of the 57-byte RFC 8032 encoding), matching the
    /// COCKTAIL-DKG test vectors.
    fn scalar_size() -> usize {
        <<Self::Group as Group>::Field as Field>::serialize(
            &<<Self::Group as Group>::Field as Field>::zero(),
        )
        .as_ref()
        .len()
    }

    /// Serialize a scalar in the COCKTAIL wire encoding.
    ///
    /// This encoding is used for the secret shares inside AEAD plaintexts,
    /// the signing key input of [`HNONCE`](Self::HNONCE), and the `z`
    /// component of COCKTAIL Schnorr signatures.
    fn serialize_scalar(scalar: &Scalar<Self>) -> Vec<u8> {
        <<Self::Group as Group>::Field as Field>::serialize(scalar)
            .as_ref()
            .to_vec()
    }

    /// Deserialize a scalar from the COCKTAIL wire encoding, rejecting
    /// non-canonical encodings (values greater than or equal to the group
    /// order).
    fn deserialize_scalar(bytes: &[u8]) -> Result<Scalar<Self>, Error<Self>> {
        let serialization =
            <<<Self::Group as Group>::Field as Field>::Serialization>::try_from(bytes)
                .map_err(|_| Error::<Self>::from(crate::FieldError::MalformedScalar))?;
        Ok(<<Self::Group as Group>::Field as Field>::deserialize(
            &serialization,
        )?)
    }

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

/// The maximum accepted size in bytes of a single encrypted share ciphertext.
///
/// The COCKTAIL-DKG specification requires implementations to enforce an
/// upper bound on individual ciphertexts as a resource-exhaustion mitigation,
/// and recommends a bound of at least 64 KiB for general-purpose
/// implementations.
pub const MAX_CIPHERTEXT_SIZE: usize = 65536;

/// Builds the `extra` input for the domain-separated H6 invocations used to
/// derive the AEAD key and nonce when the H6 output is smaller than 56 bytes:
///
/// `derive_extra(context, label) = len(context) || context || len(label) || label`
///
/// where both lengths are little-endian 64-bit integers and `label` is `"key"`
/// or `"nonce"`.
fn derive_extra(context: &[u8], label: &[u8]) -> Vec<u8> {
    let mut extra = Vec::with_capacity(16 + context.len() + label.len());
    extra.extend_from_slice(&(context.len() as u64).to_le_bytes());
    extra.extend_from_slice(context);
    extra.extend_from_slice(&(label.len() as u64).to_le_bytes());
    extra.extend_from_slice(label);
    extra
}

/// Derives a 256-bit key and 192-bit nonce from the pairwise ECDH shared
/// secrets, following the `DeriveKeyAndNonce` helper in the COCKTAIL-DKG
/// specification.
///
/// - If the H6 output is at least 56 bytes: a single `H6` call with
///   `extra = context`; `key = output[..32]`, `nonce = output[32..56]`.
/// - Otherwise: two domain-separated `H6` calls;
///   `key = H6(x, E, Ps, Pr, derive_extra(context, "key"))` and
///   `nonce = H6(x, E, Ps, Pr, derive_extra(context, "nonce"))[..24]`.
#[allow(clippy::too_many_arguments)]
fn derive_key_and_nonce<C: CocktailCiphersuite>(
    shared_secret_ephem: &[u8],
    shared_secret_static: &[u8],
    ephemeral_pub: &[u8],
    sender_pub: &[u8],
    recipient_pub: &[u8],
    context: &[u8],
) -> Result<([u8; 32], [u8; 24]), Error<C>> {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    if C::H6_OUTPUT_SIZE >= 56 {
        let h6 = C::H6(
            shared_secret_ephem,
            shared_secret_static,
            ephemeral_pub,
            sender_pub,
            recipient_pub,
            context,
        );
        key.copy_from_slice(h6.get(..32).ok_or(Error::SerializationError)?);
        nonce.copy_from_slice(h6.get(32..56).ok_or(Error::SerializationError)?);
    } else {
        let key_h6 = C::H6(
            shared_secret_ephem,
            shared_secret_static,
            ephemeral_pub,
            sender_pub,
            recipient_pub,
            &derive_extra(context, b"key"),
        );
        key.copy_from_slice(key_h6.get(..32).ok_or(Error::SerializationError)?);
        let nonce_h6 = C::H6(
            shared_secret_ephem,
            shared_secret_static,
            ephemeral_pub,
            sender_pub,
            recipient_pub,
            &derive_extra(context, b"nonce"),
        );
        nonce.copy_from_slice(nonce_h6.get(..24).ok_or(Error::SerializationError)?);
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
    msg.extend_from_slice(<C::Group>::serialize(ephemeral_pub)?.as_ref());
    Ok(msg)
}

/// Deterministic COCKTAIL Schnorr sign, used for both the Proof of Possession
/// and the Round 3 (CertEq) transcript certification.
///
/// `k = HNONCE(encode(sk), m)`, `R = k·B`, `c = H7(R, pk, m)`, `z = k + c·sk`
///
/// Per the specification, signing aborts if the deterministic nonce `k` is
/// zero (negligible probability); retrying with the same inputs would derive
/// the same `k`, so this is an unrecoverable signing failure for this
/// `(sk, m)` pair.
fn cocktail_sign<C: CocktailCiphersuite>(
    sk: Scalar<C>,
    message: &[u8],
) -> Result<Signature<C>, Error<C>> {
    let sk_bytes = C::serialize_scalar(&sk);
    let k = C::HNONCE(&sk_bytes, message);
    if k == <<C::Group as Group>::Field as Field>::zero() {
        return Err(crate::FieldError::InvalidZeroScalar.into());
    }

    let R = <C::Group>::generator() * k;
    let pk = <C::Group>::generator() * sk;

    let R_bytes = <C::Group>::serialize(&R)?;
    let pk_bytes = <C::Group>::serialize(&pk)?;
    let c = C::H7(R_bytes.as_ref(), pk_bytes.as_ref(), message);

    let z = k + c * sk;
    Ok(Signature { R, z })
}

/// Deterministic COCKTAIL Schnorr verify.
///
/// `c = H7(R, pk, m)`, check `z·B == R + c·pk`
fn cocktail_verify<C: CocktailCiphersuite>(
    pk: Element<C>,
    sig: &Signature<C>,
    message: &[u8],
) -> Result<(), Error<C>> {
    if sig.R == <C::Group>::identity() {
        return Err(Error::InvalidSignature);
    }

    let R_bytes = <C::Group>::serialize(&sig.R)?;
    let pk_bytes = <C::Group>::serialize(&pk)?;
    let c = C::H7(R_bytes.as_ref(), pk_bytes.as_ref(), message);

    let lhs = <C::Group>::generator() * sig.z;
    let rhs = sig.R + pk * c;

    if lhs != rhs {
        Err(Error::InvalidSignature)
    } else {
        Ok(())
    }
}

/// Serialize a COCKTAIL Schnorr signature (a Proof of Possession or a
/// transcript signature) as `R || z`, with `z` in the COCKTAIL scalar
/// encoding of the ciphersuite.
///
/// Note that for most ciphersuites this matches the ciphersuite's default
/// signature serialization, but e.g. Ed448 uses 56-byte scalars (113-byte
/// signatures) in COCKTAIL-DKG.
pub fn serialize_signature<C: CocktailCiphersuite>(
    sig: &Signature<C>,
) -> Result<Vec<u8>, Error<C>> {
    let mut bytes = <C::Group>::serialize(&sig.R)?.as_ref().to_vec();
    bytes.extend_from_slice(&C::serialize_scalar(&sig.z));
    Ok(bytes)
}

/// Deserialize a COCKTAIL Schnorr signature serialized with
/// [`serialize_signature`].
pub fn deserialize_signature<C: CocktailCiphersuite>(
    bytes: &[u8],
) -> Result<Signature<C>, Error<C>> {
    let elem_size = <C::Group>::serialize(&<C::Group>::generator())
        .expect("generator serialization always succeeds")
        .as_ref()
        .len();
    if bytes.len() != elem_size + C::scalar_size() {
        return Err(Error::MalformedSignature);
    }
    let R_serialization = <<C::Group as Group>::Serialization>::try_from(
        bytes.get(..elem_size).ok_or(Error::MalformedSignature)?,
    )
    .map_err(|_| Error::MalformedSignature)?;
    let R = <C::Group>::deserialize(&R_serialization)?;
    let z = C::deserialize_scalar(bytes.get(elem_size..).ok_or(Error::MalformedSignature)?)?;
    Ok(Signature { R, z })
}

/// Parsed representation of a COCKTAIL-DKG transcript.
struct Transcript<C: CocktailCiphersuite> {
    context: Vec<u8>,
    n: u16,
    t: u16,
    participants: BTreeMap<Identifier<C>, VerifyingKey<C>>,
    commitments: BTreeMap<Identifier<C>, VerifiableSecretSharingCommitment<C>>,
    ephemeral_pubs: BTreeMap<Identifier<C>, Element<C>>,
}

impl<C: CocktailCiphersuite> Transcript<C> {
    /// Parse a canonical transcript byte string into its constituent fields.
    ///
    /// The `ciphersuite_id` at the head of the transcript is validated
    /// against [`CocktailCiphersuite::COCKTAIL_ID`] before anything else is
    /// interpreted; a mismatch indicates the wrong recovery codepath and is
    /// rejected.
    ///
    /// Identifiers are reconstructed as the standard 1-based sequence `1..=n`.
    /// Returns `Err(Error::DeserializationError)` if the bytes are malformed or truncated.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error<C>> {
        let elem_size = <C::Group>::serialize(&<C::Group>::generator())
            .expect("generator serialization always succeeds")
            .as_ref()
            .len();
        let sig_size = elem_size + C::scalar_size();

        let mut pos = 0usize;

        // Returns `bytes[pos..pos+n]` and advances `pos`, or errors if out of bounds.
        let mut take = |n: usize| -> Option<&[u8]> {
            let end = pos.checked_add(n)?;
            let slice = bytes.get(pos..end)?;
            pos = end;
            Some(slice)
        };

        let id_len = u64::from_le_bytes(
            take(8)
                .ok_or(Error::DeserializationError)?
                .try_into()
                .expect("slice is 8 bytes"),
        ) as usize;
        let ciphersuite_id = take(id_len).ok_or(Error::DeserializationError)?;
        if ciphersuite_id != C::COCKTAIL_ID.as_bytes() {
            return Err(Error::DeserializationError);
        }

        let ctx_len = u64::from_le_bytes(
            take(8)
                .ok_or(Error::DeserializationError)?
                .try_into()
                .expect("slice is 8 bytes"),
        ) as usize;
        let context = take(ctx_len).ok_or(Error::DeserializationError)?.to_vec();

        let n = u32::from_le_bytes(
            take(4)
                .ok_or(Error::DeserializationError)?
                .try_into()
                .expect("slice is 4 bytes"),
        ) as u16;
        let t = u32::from_le_bytes(
            take(4)
                .ok_or(Error::DeserializationError)?
                .try_into()
                .expect("slice is 4 bytes"),
        ) as u16;

        let identifiers: Vec<Identifier<C>> = (1..=n)
            .map(Identifier::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let mut participants = BTreeMap::new();
        for &id in &identifiers {
            let pk =
                VerifyingKey::deserialize(take(elem_size).ok_or(Error::DeserializationError)?)?;
            participants.insert(id, pk);
        }

        let commitment_size = t as usize * elem_size;
        let mut commitments = BTreeMap::new();
        for &id in &identifiers {
            let c = VerifiableSecretSharingCommitment::deserialize_whole(
                take(commitment_size).ok_or(Error::DeserializationError)?,
            )?;
            commitments.insert(id, c);
        }

        // Skip the PoPs; they are not needed for recovery.
        take(sig_size * n as usize).ok_or(Error::DeserializationError)?;

        let mut ephemeral_pubs = BTreeMap::new();
        for &id in &identifiers {
            let pk =
                VerifyingKey::deserialize(take(elem_size).ok_or(Error::DeserializationError)?)?;
            ephemeral_pubs.insert(id, pk.to_element());
        }

        let ext_len = u64::from_le_bytes(
            take(8)
                .ok_or(Error::DeserializationError)?
                .try_into()
                .expect("slice is 8 bytes"),
        ) as usize;
        take(ext_len).ok_or(Error::DeserializationError)?; // extension (not needed for recovery)

        if pos != bytes.len() {
            return Err(Error::DeserializationError);
        }

        Ok(Self {
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
    /// 1. `len(ciphersuite_id)` as little-endian u64
    /// 2. `ciphersuite_id` (UTF-8 bytes)
    /// 3. `len(context)` as little-endian u64
    /// 4. `context`
    /// 5. `n` as little-endian u32
    /// 6. `t` as little-endian u32
    /// 7. `P_j` for each participant in identifier-sorted order
    /// 8. `C_j` (full VSS commitment) for each participant in identifier-sorted order
    /// 9. `PoP_j` for each participant in identifier-sorted order
    /// 10. `E_j` for each participant in identifier-sorted order
    /// 11. `len(ext)` as little-endian u64
    /// 12. `ext`
    fn serialize(
        &self,
        pops: &BTreeMap<Identifier<C>, Signature<C>>,
        extension: &[u8],
    ) -> Result<Vec<u8>, Error<C>> {
        let mut t_bytes = Vec::new();

        t_bytes.extend_from_slice(&(C::COCKTAIL_ID.len() as u64).to_le_bytes());
        t_bytes.extend_from_slice(C::COCKTAIL_ID.as_bytes());
        t_bytes.extend_from_slice(&(self.context.len() as u64).to_le_bytes());
        t_bytes.extend_from_slice(&self.context);
        t_bytes.extend_from_slice(&(self.n as u32).to_le_bytes());
        t_bytes.extend_from_slice(&(self.t as u32).to_le_bytes());

        for pk in self.participants.values() {
            t_bytes.extend_from_slice(&pk.serialize()?);
        }
        for id in self.participants.keys() {
            let c = self.commitments.get(id).ok_or(Error::PackageNotFound)?;
            t_bytes.extend_from_slice(&c.serialize_whole()?);
        }
        for id in self.participants.keys() {
            let pop = pops.get(id).ok_or(Error::PackageNotFound)?;
            t_bytes.extend_from_slice(&serialize_signature(pop)?);
        }
        for id in self.participants.keys() {
            let e = self.ephemeral_pubs.get(id).ok_or(Error::PackageNotFound)?;
            t_bytes.extend_from_slice(<C::Group>::serialize(e)?.as_ref());
        }

        t_bytes.extend_from_slice(&(extension.len() as u64).to_le_bytes());
        t_bytes.extend_from_slice(extension);

        Ok(t_bytes)
    }
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

/// Validates the participant map used in the COCKTAIL-DKG setup.
///
/// Per the specification, the identifiers must be the contiguous sequence
/// `1..=max_signers` (in the canonical, agreed-upon participant ordering) and
/// all static public keys must be distinct valid points; disagreement is a
/// setup failure.
fn validate_participants<C: CocktailCiphersuite>(
    participants: &BTreeMap<Identifier<C>, VerifyingKey<C>>,
    max_signers: u16,
) -> Result<(), Error<C>> {
    if participants.len() != max_signers as usize {
        return Err(Error::IncorrectNumberOfIdentifiers);
    }
    for (i, id) in participants.keys().enumerate() {
        if *id != Identifier::<C>::try_from(i as u16 + 1)? {
            return Err(Error::MalformedIdentifier);
        }
    }
    let distinct_keys: BTreeSet<Vec<u8>> = participants
        .values()
        .map(|pk| pk.serialize())
        .collect::<Result<_, _>>()?;
    if distinct_keys.len() != participants.len() {
        return Err(Error::DuplicatedVerifyingKeys);
    }
    Ok(())
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
///   Must include the calling participant's own key, have exactly `max_signers` entries
///   with the contiguous identifiers `1..=max_signers`, and contain no duplicate keys.
/// - `context`: A session-unique context string. It is **RECOMMENDED** to construct this as
///   `H("COCKTAIL-DKG-CONTEXT" || uint64_be(len(session_id)) || session_id ||
///   uint64_be(len(ciphersuite_id)) || ciphersuite_id || uint32_le(n) || P_1 || ... || P_n)`,
///   which binds the session, the ciphersuite, and the ordered participant set as
///   required by the specification.
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
    validate_participants(participants, max_signers)?;

    if !participants.contains_key(&identifier) {
        return Err(Error::UnknownIdentifier);
    }

    // Steps 1 & 3: Generate secret polynomial and VSS commitment.
    // All coefficients are sampled nonzero per the specification, so that
    // every commitment point is a non-identity point.
    let secret: SigningKey<C> = SigningKey::new(&mut rng);
    let coefficients: Vec<Scalar<C>> = (0..min_signers as usize - 1)
        .map(|_| random_nonzero::<C, R>(&mut rng))
        .collect();
    let (coefficients, commitment) =
        generate_secret_polynomial(&secret, max_signers, min_signers, coefficients)?;

    // Step 3: Generate ephemeral key pair (e_i, E_i); e_i is sampled nonzero
    // so that E_i is a non-identity point.
    let ephemeral_privkey = random_nonzero::<C, R>(&mut rng);
    let ephemeral_pubkey = <C::Group>::generator() * ephemeral_privkey;

    // Step 4: Compute proof of possession using the COCKTAIL deterministic
    // Schnorr scheme. Sign `context || C_i || E_i` using a_{i,0} as the
    // signing key.
    let a_i0 = *coefficients
        .first()
        .expect("coefficients has at least one element");
    let pop_msg = pop_message::<C>(&commitment, &ephemeral_pubkey, context)?;
    let proof_of_possession = cocktail_sign::<C>(a_i0, &pop_msg)?;

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

        let (key, nonce) = derive_key_and_nonce::<C>(
            <C::Group>::serialize(&s_ephem)?.as_ref(),
            <C::Group>::serialize(&s_static)?.as_ref(),
            &ephemeral_pubkey_bytes,
            &sender_pubkey_bytes,
            &recipient_pubkey.serialize()?,
            context,
        )?;

        // Plaintext = share bytes || optional application payload
        let mut plaintext = C::serialize_scalar(&share);
        if let Some(payload) = payloads.get(recipient_id) {
            plaintext.extend_from_slice(payload);
        }
        let ciphertext = C::aead_encrypt(&key, &nonce, &plaintext);
        if ciphertext.len() > MAX_CIPHERTEXT_SIZE {
            // Recipients enforce the same bound and would reject this
            // ciphertext, so fail fast on the sender side.
            return Err(Error::SerializationError);
        }
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
pub fn part2<C: CocktailCiphersuite>(
    secret_package: round1::SecretPackage<C>,
    round1_packages: &BTreeMap<Identifier<C>, round1::Package<C>>,
    static_signing_key: &SigningKey<C>,
    participants: &BTreeMap<Identifier<C>, VerifyingKey<C>>,
    context: &[u8],
    extension: &[u8],
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
    validate_participants(participants, secret_package.max_signers)?;

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
        cocktail_verify::<C>(
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

        let (key, nonce) = derive_key_and_nonce::<C>(
            <C::Group>::serialize(&s_ephemeral)?.as_ref(),
            <C::Group>::serialize(&s_static)?.as_ref(),
            <C::Group>::serialize(&package.ephemeral_pub)?.as_ref(),
            &sender_pubkey.serialize()?,
            &my_pub_bytes,
            context,
        )?;

        let ciphertext = package
            .encrypted_shares
            .get(&my_id)
            .ok_or(Error::PackageNotFound)?;

        // Enforce the ciphertext size bounds from the specification: at least
        // the size of a zero-payload encrypted share, at most the
        // resource-exhaustion cap.
        let scalar_len = C::scalar_size();
        if ciphertext.len() < scalar_len + C::AEAD_TAG_SIZE
            || ciphertext.len() > MAX_CIPHERTEXT_SIZE
        {
            return Err(Error::DecryptionFailed {
                culprit: *sender_id,
            });
        }

        let plaintext =
            C::aead_decrypt(&key, &nonce, ciphertext).map_err(|_| Error::DecryptionFailed {
                culprit: *sender_id,
            })?;

        // Parse: first scalar_len bytes are s_{j,i}; rest is optional payload.
        // A plaintext that is too short or whose leading portion is not a
        // canonical scalar identifies the sender as malicious.
        let share_bytes = plaintext
            .get(..scalar_len)
            .ok_or(Error::InvalidSecretShare {
                culprit: Some(*sender_id),
            })?;
        let s_j_i = C::deserialize_scalar(share_bytes).map_err(|_| Error::InvalidSecretShare {
            culprit: Some(*sender_id),
        })?;

        // Collect optional payload (remainder after the share bytes)
        let payload = plaintext
            .get(scalar_len..)
            .ok_or(Error::InvalidSecretShare {
                culprit: Some(*sender_id),
            })?
            .to_vec();
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

    // Build transcript and sign it with d_i using the deterministic COCKTAIL
    // Schnorr scheme (the same scheme used for the PoP).
    let transcript_data = Transcript {
        context: context.to_vec(),
        n: secret_package.max_signers,
        t: secret_package.min_signers,
        participants: participants.clone(),
        commitments: all_commitments,
        ephemeral_pubs: all_ephemeral_pubs,
    };
    let transcript = transcript_data.serialize(&all_pops, &effective_extension)?;
    let transcript_signature = cocktail_sign::<C>(d_i, &transcript)?;

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

    // Verify all n transcript signatures using the COCKTAIL Schnorr scheme
    for (signer_id, package) in round2_packages.iter() {
        let signer_pubkey = secret_package
            .participants
            .get(signer_id)
            .ok_or(Error::UnknownIdentifier)?;

        cocktail_verify::<C>(
            signer_pubkey.to_element(),
            &package.transcript_signature,
            &secret_package.transcript,
        )
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
/// - `ciphertexts`: The participant-specific encrypted share bundle: the encrypted
///   shares $c_{j,i}$ from each sender $j$ to the recovering participant $i$, keyed
///   by sender identifier, with exactly one entry per participant. These are the
///   per-recipient (unframed) ciphertexts from each sender's [`round1::Package`].
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
    // Step 1: Extract parameters. This validates the ciphersuite identifier
    // at the head of the transcript before any signature is checked, since
    // the signature scheme itself is ciphersuite-dependent.
    let parsed = Transcript::<C>::deserialize(transcript)?;

    // Step 2: Validate the success certificate using the COCKTAIL Schnorr scheme.
    if success_certificate.len() != parsed.n as usize {
        return Err(Error::IncorrectNumberOfPackages);
    }
    for (signer_id, sig) in success_certificate {
        let pk = parsed
            .participants
            .get(signer_id)
            .ok_or(Error::UnknownIdentifier)?;
        cocktail_verify::<C>(pk.to_element(), sig, transcript).map_err(|_| {
            Error::InvalidTranscriptSignature {
                culprit: *signer_id,
            }
        })?;
    }

    // Step 3: Find the unique identifier matching d_i * B in the participant
    // list. Zero or more than one match aborts.
    let my_pub = VerifyingKey::from(static_signing_key);
    let mut matches = parsed.participants.iter().filter(|(_, pk)| **pk == my_pub);
    let my_id = *matches.next().ok_or(Error::UnknownIdentifier)?.0;
    if matches.next().is_some() {
        return Err(Error::DuplicatedVerifyingKeys);
    }

    let my_pub_bytes = my_pub.serialize()?;
    let d_i = static_signing_key.to_scalar();

    let scalar_len = C::scalar_size();

    // The encrypted share bundle must contain exactly one ciphertext per
    // participant, with no extra entries.
    if ciphertexts.len() != parsed.n as usize {
        return Err(Error::IncorrectNumberOfPackages);
    }

    // Steps 4–7: For each sender j, derive decryption key, decrypt, verify, and accumulate.
    let mut signing_share_scalar = <<C::Group as Group>::Field>::zero();

    for (&sender_id, sender_pub) in &parsed.participants {
        let ephemeral_pub = parsed
            .ephemeral_pubs
            .get(&sender_id)
            .ok_or(Error::PackageNotFound)?;
        let ciphertext = ciphertexts.get(&sender_id).ok_or(Error::PackageNotFound)?;

        // Enforce the ciphertext size bounds from the specification.
        if ciphertext.len() < scalar_len + C::AEAD_TAG_SIZE
            || ciphertext.len() > MAX_CIPHERTEXT_SIZE
        {
            return Err(Error::DecryptionFailed { culprit: sender_id });
        }

        // S^(e)_{j,i} = d_i * E_j  and  S^(d)_{j,i} = d_i * P_j
        let s_ephem = *ephemeral_pub * d_i;
        let s_static = sender_pub.to_element() * d_i;

        let (key, nonce) = derive_key_and_nonce::<C>(
            <C::Group>::serialize(&s_ephem)?.as_ref(),
            <C::Group>::serialize(&s_static)?.as_ref(),
            <C::Group>::serialize(ephemeral_pub)?.as_ref(),
            &sender_pub.serialize()?,
            &my_pub_bytes,
            &parsed.context,
        )?;

        let plaintext = C::aead_decrypt(&key, &nonce, ciphertext)
            .map_err(|_| Error::DecryptionFailed { culprit: sender_id })?;

        // A plaintext that is too short or whose leading portion is not a
        // canonical scalar aborts the recovery.
        let share_bytes = plaintext
            .get(..scalar_len)
            .ok_or(Error::InvalidSecretShare {
                culprit: Some(sender_id),
            })?;
        let s_j_i = C::deserialize_scalar(share_bytes).map_err(|_| Error::InvalidSecretShare {
            culprit: Some(sender_id),
        })?;

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
