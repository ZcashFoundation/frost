//! FROST Error types

use thiserror::Error;

/// An error related to FROST.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
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
    /// Signature verification failed.
    #[error("Invalid signature.")]
    InvalidSignature,
}
