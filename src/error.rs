use thiserror::Error;

/// An error related to RedJubJub signatures.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// The encoding of a signing key was malformed.
    #[error("Malformed signing key encoding.")]
    MalformedSigningKey,
    /// The encoding of a verification key was malformed.
    #[error("Malformed verification key encoding.")]
    MalformedVerificationKey,
    /// Signature verification failed.
    #[error("Invalid signature.")]
    InvalidSignature,
}
