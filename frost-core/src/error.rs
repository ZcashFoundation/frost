//! FROST Error types

use thiserror::Error;

/// An error related to FROST.
#[non_exhaustive]
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// This identifier is unserializable.
    #[error("Malformed identifier is unserializable.")]
    MalformedIdentifier,
    /// The encoding of a group scalar was malformed.
    #[error("Malformed scalar encoding.")]
    MalformedScalar,
    /// The encoding of a group element was malformed.
    #[error("Malformed group element encoding.")]
    MalformedElement,
    /// The encoding of a signing key was malformed.
    #[error("Malformed signing key encoding.")]
    MalformedSigningKey,
    /// The encoding of a verifying key was malformed.
    #[error("Malformed verifying key encoding.")]
    MalformedVerifyingKey,
    /// The encoding of a signature was malformed.
    #[error("Malformed signature encoding.")]
    MalformedSignature,
    /// Signature verification failed.
    #[error("Invalid signature.")]
    InvalidSignature,
    /// This scalar MUST NOT be zero.
    #[error("Invalid for this scalar to be zero.")]
    InvalidZeroScalar,
    /// This element MUST NOT be the identity.
    #[error("Invalid for this element to be the identity.")]
    InvalidIdentityElement,
}
