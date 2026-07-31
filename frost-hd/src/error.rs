//! Error types.

use core::fmt;

/// Errors returned by the experimental HD derivation API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The application, network, purpose, or ciphersuite identifier exceeds
    /// the canonical `u16` length bound.
    ContextComponentTooLong,
    /// A derivation path exceeds [`crate::MAX_PATH_DEPTH`].
    PathTooDeep,
    /// A textual path is not in canonical form.
    NonCanonicalPath,
    /// A path index does not fit in a `u32`.
    PathIndexOverflow,
    /// A binary path uses an unsupported serialization version.
    UnsupportedPathVersion,
    /// A binary path uses an unknown segment kind.
    UnknownSegmentKind,
    /// A binary path is truncated or contains trailing bytes.
    MalformedPathEncoding,
    /// Root path `m` cannot be converted into a signable child package.
    RootPathNotSignable,
    /// `FROST-HD-v1` does not support hardened derivation.
    HardenedDerivationUnsupported,
    /// The parent joint verifying key could not be serialized canonically.
    ParentKeySerialization,
    /// HMAC initialization failed. HMAC accepts keys of any size, so this
    /// indicates an unexpected library-level failure.
    KdfInitialization,
    /// Every deterministic retry candidate was invalid.
    RetryExhausted,
    /// A derived participant verifying share is the group identity.
    DerivedVerifyingShareIdentity,
    /// A private package is not internally consistent with its signing share.
    InconsistentPrivatePackage,
    /// A private child package does not match the expected public child package.
    PrivatePublicMismatch,
    /// Private and public roots do not bind to the same family metadata.
    FamilyMetadataMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ContextComponentTooLong => "derivation context component exceeds u16 length",
            Self::PathTooDeep => "derivation path exceeds the maximum depth",
            Self::NonCanonicalPath => "non-canonical derivation path",
            Self::PathIndexOverflow => "derivation path index exceeds u32",
            Self::UnsupportedPathVersion => "unsupported derivation path version",
            Self::UnknownSegmentKind => "unknown derivation path segment kind",
            Self::MalformedPathEncoding => "malformed derivation path encoding",
            Self::RootPathNotSignable => "the HD root cannot be exposed as a signable child",
            Self::HardenedDerivationUnsupported => "hardened derivation is unsupported",
            Self::ParentKeySerialization => "failed to serialize the parent verifying key",
            Self::KdfInitialization => "failed to initialize the derivation KDF",
            Self::RetryExhausted => "deterministic derivation retry space exhausted",
            Self::DerivedVerifyingShareIdentity => {
                "derived participant verifying share is the identity"
            }
            Self::InconsistentPrivatePackage => "private key package is internally inconsistent",
            Self::PrivatePublicMismatch => {
                "derived private package does not match the public package"
            }
            Self::FamilyMetadataMismatch => "private and public family metadata do not match",
        })
    }
}
