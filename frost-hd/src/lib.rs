//! Experimental, ciphersuite-agnostic, non-hardened hierarchical key
//! derivation for FROST key packages.
//!
//! # Security model
//!
//! For a public child tweak `t`, this crate transforms the participant shares
//! and public keys as follows:
//!
//! ```text
//! s_i' = s_i + t
//! Y_i' = Y_i + tG
//! Y'   = Y   + tG
//! ```
//!
//! This is a **related-key** construction. A child signing share and the public
//! derivation metadata reveal the corresponding parent signing share. Derived
//! children therefore do not provide the compromise compartmentalization of
//! independent DKG executions.
//!
//! This crate is an unaudited research prototype. It does not implement
//! hardened derivation, BIP32 serialization, Taproot wallet policy, Solana
//! address encoding, or SLIP-0010 compatibility.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::indexing_slicing)]

extern crate alloc;

mod error;
mod path;

use alloc::{collections::BTreeMap, vec::Vec};
use core::{fmt, marker::PhantomData};

pub use error::Error;
use frost_core::{
    Ciphersuite, Field, Group, Scalar, VerifyingKey,
    keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare},
};
use hmac::{Hmac, KeyInit, Mac};
pub use path::{DerivationPath, PathSegment};
use sha2::{Digest, Sha256, Sha512};

/// The protocol version encoded in every KDF transcript.
pub const KEY_FAMILY_VERSION: u16 = 1;
/// The canonical path serialization version.
pub const PATH_ENCODING_VERSION: u16 = 1;
/// Maximum number of path segments accepted by the parser and derivation API.
pub const MAX_PATH_DEPTH: usize = 64;
/// Number of deterministic retry values available for one derivation edge.
pub const MAX_EDGE_RETRIES: u32 = u16::MAX as u32 + 1;

const DST_CONTEXT: &[u8] = b"FROST-HD-v1/context";
const DST_EDGE: &[u8] = b"FROST-HD-v1/edge";
const DST_TWEAK_PRF: &[u8] = b"FROST-HD-v1/tweak-prf";
const DST_CHILD_KEY: &[u8] = b"FROST-HD-v1/child-derivation-key";
const DST_HASH_TO_SCALAR: &[u8] = b"FROST-HD-v1/hash-to-scalar";

type HmacSha512 = Hmac<Sha512>;

/// Public 32-byte metadata used to derive a deterministic child family.
///
/// This value is not assumed secret. Disclosing it intentionally permits
/// descendant enumeration and, when combined with a child signing share,
/// parent-share recovery.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DerivationKey([u8; 32]);

impl DerivationKey {
    /// Creates a derivation key from authenticated application-provided bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical bytes.
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for DerivationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key is public protocol metadata, but redaction avoids accidental
        // correlation through logs and keeps applications honest about where
        // family metadata is intentionally disclosed.
        formatter.debug_tuple("DerivationKey").field(&"<redacted>").finish()
    }
}

/// Blockchain-agnostic application context for one key family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationContext {
    application: Vec<u8>,
    network: Vec<u8>,
    purpose: Vec<u8>,
}

impl DerivationContext {
    /// Creates a context from opaque application, network, and purpose labels.
    pub fn new(
        application: impl Into<Vec<u8>>,
        network: impl Into<Vec<u8>>,
        purpose: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        let context = Self {
            application: application.into(),
            network: network.into(),
            purpose: purpose.into(),
        };
        for component in [&context.application, &context.network, &context.purpose] {
            if component.len() > u16::MAX as usize {
                return Err(Error::ContextComponentTooLong);
            }
        }
        Ok(context)
    }

    /// Returns the application label.
    pub fn application(&self) -> &[u8] {
        &self.application
    }

    /// Returns the network label.
    pub fn network(&self) -> &[u8] {
        &self.network
    }

    /// Returns the purpose label.
    pub fn purpose(&self) -> &[u8] {
        &self.purpose
    }

    /// Computes the ciphersuite-bound canonical context digest.
    pub fn digest<C, P>(&self) -> Result<ContextDigest, Error>
    where
        C: Ciphersuite,
        P: DerivationProfile<C>,
    {
        let mut hasher = Sha256::new();
        hasher.update(DST_CONTEXT);
        hasher.update(KEY_FAMILY_VERSION.to_be_bytes());
        hash_lp16(&mut hasher, C::ID.as_bytes())?;
        hash_lp16(&mut hasher, P::ID.as_bytes())?;
        hash_lp16(&mut hasher, &self.application)?;
        hash_lp16(&mut hasher, &self.network)?;
        hash_lp16(&mut hasher, &self.purpose)?;
        let output = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(output.as_ref());
        Ok(ContextDigest(digest))
    }
}

/// A ciphersuite-bound digest of the application context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextDigest([u8; 32]);

impl ContextDigest {
    /// Returns the canonical digest bytes.
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// An explicit cryptographic profile for persistent HD derivation.
///
/// Implementing this trait is an opt-in security decision. It prevents the
/// generic crate from silently claiming support for every FROST ciphersuite,
/// including ciphersuites whose key normalization or signing semantics are not
/// linear under a persistent additive tweak.
///
/// A profile identifier is included in every context and edge transcript.
/// Changing the profile identifier or scalar mapping creates a distinct key
/// family.
pub trait DerivationProfile<C: Ciphersuite>: Copy + fmt::Debug + Send + Sync + 'static {
    /// Stable, globally unique identifier for the profile and its scalar
    /// mapping, including a version suffix.
    const ID: &'static str;

    /// Maps a domain-separated PRF output to a scalar in `C`'s scalar field.
    ///
    /// Implementations MUST be deterministic, uniformly distributed to the
    /// security level required by the ciphersuite, and reviewed for the target
    /// ciphersuite. Returning zero is allowed; the edge algorithm retries
    /// deterministically.
    fn hash_to_scalar(input: &[u8]) -> Scalar<C>;
}

/// Non-signable wrapper for one participant's root key package.
///
/// This type intentionally exposes no accessor for the inner root package.
/// Applications can only derive descendants from it.
pub struct HdRootKeyPackage<C, P>
where
    C: Ciphersuite,
    P: DerivationProfile<C>,
{
    key_package: KeyPackage<C>,
    derivation_key: DerivationKey,
    context: ContextDigest,
    _profile: PhantomData<P>,
}

impl<C, P> HdRootKeyPackage<C, P>
where
    C: Ciphersuite,
    P: DerivationProfile<C>,
{
    /// Binds a root participant package to authenticated family metadata.
    pub fn new(
        key_package: KeyPackage<C>,
        derivation_key: DerivationKey,
        context: ContextDigest,
    ) -> Result<Self, Error> {
        validate_private_package(&key_package)?;
        Ok(Self {
            key_package,
            derivation_key,
            context,
            _profile: PhantomData,
        })
    }

    /// Derives one direct normal child.
    pub fn derive_child(&self, index: u32) -> Result<ExtendedKeyPackage<C, P>, Error> {
        derive_private_node::<C, P>(
            &self.key_package,
            self.derivation_key,
            self.context,
            &DerivationPath::root(),
            PathSegment::Normal(index),
        )
    }

    /// Derives a descendant by evaluating the canonical path left to right.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<ExtendedKeyPackage<C, P>, Error> {
        if path.depth() == 0 {
            return Err(Error::RootPathNotSignable);
        }
        let mut current_package = self.key_package.clone();
        let mut current_key = self.derivation_key;
        let mut current_path = DerivationPath::root();

        for segment in path.segments() {
            let derived = derive_private_node::<C, P>(
                &current_package,
                current_key,
                self.context,
                &current_path,
                *segment,
            )?;
            current_package = derived.key_package;
            current_key = derived.derivation_key;
            current_path = derived.path;
        }

        Ok(ExtendedKeyPackage {
            key_package: current_package,
            derivation_key: current_key,
            context: self.context,
            path: current_path,
            _profile: PhantomData,
        })
    }
}

/// Non-address wrapper for a root public package.
///
/// The root public key is retained internally to derive descendants. The API
/// intentionally does not expose it as an ordinary child/address object.
#[derive(Clone)]
pub struct HdRootPublicKeyPackage<C, P>
where
    C: Ciphersuite,
    P: DerivationProfile<C>,
{
    public_key_package: PublicKeyPackage<C>,
    derivation_key: DerivationKey,
    context: ContextDigest,
    _profile: PhantomData<P>,
}

impl<C, P> HdRootPublicKeyPackage<C, P>
where
    C: Ciphersuite,
    P: DerivationProfile<C>,
{
    /// Binds a root public package to authenticated family metadata.
    pub fn new(
        public_key_package: PublicKeyPackage<C>,
        derivation_key: DerivationKey,
        context: ContextDigest,
    ) -> Self {
        Self {
            public_key_package,
            derivation_key,
            context,
            _profile: PhantomData,
        }
    }

    /// Derives one direct normal public child.
    pub fn derive_child(&self, index: u32) -> Result<ExtendedPublicKeyPackage<C, P>, Error> {
        derive_public_node::<C, P>(
            &self.public_key_package,
            self.derivation_key,
            self.context,
            &DerivationPath::root(),
            PathSegment::Normal(index),
        )
    }

    /// Derives a public descendant by evaluating the path left to right.
    pub fn derive_path(
        &self,
        path: &DerivationPath,
    ) -> Result<ExtendedPublicKeyPackage<C, P>, Error> {
        if path.depth() == 0 {
            return Err(Error::RootPathNotSignable);
        }
        let mut current_package = self.public_key_package.clone();
        let mut current_key = self.derivation_key;
        let mut current_path = DerivationPath::root();

        for segment in path.segments() {
            let derived = derive_public_node::<C, P>(
                &current_package,
                current_key,
                self.context,
                &current_path,
                *segment,
            )?;
            current_package = derived.public_key_package;
            current_key = derived.derivation_key;
            current_path = derived.path;
        }

        Ok(ExtendedPublicKeyPackage {
            public_key_package: current_package,
            derivation_key: current_key,
            context: self.context,
            path: current_path,
            _profile: PhantomData,
        })
    }
}

/// One participant's derived signing package plus public family metadata.
pub struct ExtendedKeyPackage<C, P>
where
    C: Ciphersuite,
    P: DerivationProfile<C>,
{
    key_package: KeyPackage<C>,
    derivation_key: DerivationKey,
    context: ContextDigest,
    path: DerivationPath,
    _profile: PhantomData<P>,
}

impl<C, P> ExtendedKeyPackage<C, P>
where
    C: Ciphersuite,
    P: DerivationProfile<C>,
{
    /// Returns the child key package that may be used with ordinary FROST
    /// signing APIs.
    pub fn key_package(&self) -> &KeyPackage<C> {
        &self.key_package
    }

    /// Returns the current node's derivation key.
    pub const fn derivation_key(&self) -> DerivationKey {
        self.derivation_key
    }

    /// Returns the ciphersuite-bound context digest.
    pub const fn context(&self) -> ContextDigest {
        self.context
    }

    /// Returns the canonical path from the root.
    pub fn path(&self) -> &DerivationPath {
        &self.path
    }

    /// Derives one direct descendant.
    pub fn derive_child(&self, segment: PathSegment) -> Result<Self, Error> {
        derive_private_node::<C, P>(
            &self.key_package,
            self.derivation_key,
            self.context,
            &self.path,
            segment,
        )
    }

    /// Checks that this participant package and an extended public package
    /// describe the same family node and participant verification share.
    pub fn matches_public(&self, public: &ExtendedPublicKeyPackage<C, P>) -> Result<(), Error> {
        if self.derivation_key != public.derivation_key
            || self.context != public.context
            || self.path != public.path
            || self.key_package.verifying_key() != public.public_key_package.verifying_key()
        {
            return Err(Error::FamilyMetadataMismatch);
        }
        let expected = public
            .public_key_package
            .verifying_shares()
            .get(self.key_package.identifier())
            .ok_or(Error::PrivatePublicMismatch)?;
        if expected != self.key_package.verifying_share() {
            return Err(Error::PrivatePublicMismatch);
        }
        Ok(())
    }
}

/// A derived public package plus public family metadata.
#[derive(Clone)]
pub struct ExtendedPublicKeyPackage<C, P>
where
    C: Ciphersuite,
    P: DerivationProfile<C>,
{
    public_key_package: PublicKeyPackage<C>,
    derivation_key: DerivationKey,
    context: ContextDigest,
    path: DerivationPath,
    _profile: PhantomData<P>,
}

impl<C, P> ExtendedPublicKeyPackage<C, P>
where
    C: Ciphersuite,
    P: DerivationProfile<C>,
{
    /// Returns the public package used for aggregation and signature
    /// verification at this child node.
    pub fn public_key_package(&self) -> &PublicKeyPackage<C> {
        &self.public_key_package
    }

    /// Returns the current node's derivation key.
    pub const fn derivation_key(&self) -> DerivationKey {
        self.derivation_key
    }

    /// Returns the ciphersuite-bound context digest.
    pub const fn context(&self) -> ContextDigest {
        self.context
    }

    /// Returns the canonical path from the root.
    pub fn path(&self) -> &DerivationPath {
        &self.path
    }

    /// Derives one direct public descendant.
    pub fn derive_child(&self, segment: PathSegment) -> Result<Self, Error> {
        derive_public_node::<C, P>(
            &self.public_key_package,
            self.derivation_key,
            self.context,
            &self.path,
            segment,
        )
    }
}

struct Edge<C: Ciphersuite> {
    tweak: Scalar<C>,
    tweak_element: <C::Group as Group>::Element,
    child_derivation_key: DerivationKey,
}

fn derive_private_node<C, P>(
    parent: &KeyPackage<C>,
    parent_derivation_key: DerivationKey,
    context: ContextDigest,
    parent_path: &DerivationPath,
    segment: PathSegment,
) -> Result<ExtendedKeyPackage<C, P>, Error>
where
    C: Ciphersuite,
    P: DerivationProfile<C>,
{
    let edge = derive_edge::<C, P>(
        parent.verifying_key(),
        parent_derivation_key,
        context,
        segment,
    )?;
    let signing_share = SigningShare::new(parent.signing_share().to_scalar() + edge.tweak);
    let verifying_share_element = parent.verifying_share().to_element() + edge.tweak_element;
    if verifying_share_element == <C::Group as Group>::identity() {
        return Err(Error::DerivedVerifyingShareIdentity);
    }
    let verifying_share = VerifyingShare::new(verifying_share_element);
    if VerifyingShare::from(signing_share) != verifying_share {
        return Err(Error::InconsistentPrivatePackage);
    }
    let verifying_key = VerifyingKey::new(parent.verifying_key().to_element() + edge.tweak_element);
    let key_package = KeyPackage::new(
        *parent.identifier(),
        signing_share,
        verifying_share,
        verifying_key,
        *parent.min_signers(),
    );

    Ok(ExtendedKeyPackage {
        key_package,
        derivation_key: edge.child_derivation_key,
        context,
        path: parent_path.child(segment)?,
        _profile: PhantomData,
    })
}

fn derive_public_node<C, P>(
    parent: &PublicKeyPackage<C>,
    parent_derivation_key: DerivationKey,
    context: ContextDigest,
    parent_path: &DerivationPath,
    segment: PathSegment,
) -> Result<ExtendedPublicKeyPackage<C, P>, Error>
where
    C: Ciphersuite,
    P: DerivationProfile<C>,
{
    let edge = derive_edge::<C, P>(
        parent.verifying_key(),
        parent_derivation_key,
        context,
        segment,
    )?;
    let mut verifying_shares = BTreeMap::new();
    for (identifier, verifying_share) in parent.verifying_shares() {
        let element = verifying_share.to_element() + edge.tweak_element;
        if element == <C::Group as Group>::identity() {
            return Err(Error::DerivedVerifyingShareIdentity);
        }
        verifying_shares.insert(*identifier, VerifyingShare::new(element));
    }
    let verifying_key = VerifyingKey::new(parent.verifying_key().to_element() + edge.tweak_element);
    let public_key_package =
        PublicKeyPackage::new(verifying_shares, verifying_key, parent.min_signers());

    Ok(ExtendedPublicKeyPackage {
        public_key_package,
        derivation_key: edge.child_derivation_key,
        context,
        path: parent_path.child(segment)?,
        _profile: PhantomData,
    })
}

fn derive_edge<C, P>(
    parent_verifying_key: &VerifyingKey<C>,
    parent_derivation_key: DerivationKey,
    context: ContextDigest,
    segment: PathSegment,
) -> Result<Edge<C>, Error>
where
    C: Ciphersuite,
    P: DerivationProfile<C>,
{
    if segment.is_hardened() {
        return Err(Error::HardenedDerivationUnsupported);
    }
    let serialized_parent = parent_verifying_key
        .serialize()
        .map_err(|_| Error::ParentKeySerialization)?;
    if C::ID.len() > u16::MAX as usize
        || P::ID.len() > u16::MAX as usize
        || serialized_parent.len() > u16::MAX as usize
    {
        return Err(Error::ContextComponentTooLong);
    }

    for retry in 0..MAX_EDGE_RETRIES {
        let retry = retry as u16;
        let mut common = Vec::with_capacity(
            DST_EDGE.len()
                + 2
                + 2
                + C::ID.len()
                + 2
                + P::ID.len()
                + 32
                + 2
                + serialized_parent.len()
                + 1
                + 4
                + 2,
        );
        common.extend_from_slice(DST_EDGE);
        common.extend_from_slice(&KEY_FAMILY_VERSION.to_be_bytes());
        append_lp16(&mut common, C::ID.as_bytes())?;
        append_lp16(&mut common, P::ID.as_bytes())?;
        common.extend_from_slice(&context.0);
        append_lp16(&mut common, &serialized_parent)?;
        common.push(segment.kind());
        common.extend_from_slice(&segment.index().to_be_bytes());
        common.extend_from_slice(&retry.to_be_bytes());

        let tweak_prf = hmac_sha512(parent_derivation_key.0, DST_TWEAK_PRF, &common)?;
        let mut scalar_input = Vec::with_capacity(DST_HASH_TO_SCALAR.len() + tweak_prf.len());
        scalar_input.extend_from_slice(DST_HASH_TO_SCALAR);
        scalar_input.extend_from_slice(&tweak_prf);
        let tweak = P::hash_to_scalar(&scalar_input);
        if tweak == <<C::Group as Group>::Field as Field>::zero() {
            continue;
        }
        let tweak_element = <C::Group as Group>::generator() * tweak;
        let child_verifying_key = parent_verifying_key.to_element() + tweak_element;
        if child_verifying_key == <C::Group as Group>::identity() {
            continue;
        }

        let child_prf = hmac_sha512(parent_derivation_key.0, DST_CHILD_KEY, &common)?;
        let mut child_derivation_key = [0u8; 32];
        let (child_key_bytes, _) = child_prf.split_at(32);
        child_derivation_key.copy_from_slice(child_key_bytes);
        return Ok(Edge {
            tweak,
            tweak_element,
            child_derivation_key: DerivationKey(child_derivation_key),
        });
    }
    Err(Error::RetryExhausted)
}

fn validate_private_package<C: Ciphersuite>(package: &KeyPackage<C>) -> Result<(), Error> {
    if VerifyingShare::from(*package.signing_share()) == *package.verifying_share() {
        Ok(())
    } else {
        Err(Error::InconsistentPrivatePackage)
    }
}

fn hmac_sha512(
    key: [u8; 32],
    domain: &[u8],
    common: &[u8],
) -> Result<[u8; 64], Error> {
    let mut mac = HmacSha512::new_from_slice(&key).map_err(|_| Error::KdfInitialization)?;
    mac.update(domain);
    mac.update(common);
    let output = mac.finalize().into_bytes();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(output.as_ref());
    Ok(bytes)
}

fn hash_lp16(hasher: &mut Sha256, value: &[u8]) -> Result<(), Error> {
    if value.len() > u16::MAX as usize {
        return Err(Error::ContextComponentTooLong);
    }
    hasher.update((value.len() as u16).to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn append_lp16(output: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
    if value.len() > u16::MAX as usize {
        return Err(Error::ContextComponentTooLong);
    }
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}
