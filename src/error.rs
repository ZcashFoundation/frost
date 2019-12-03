use thiserror::Error;

/// An error related to RedJubJub signatures.
#[derive(Error, Debug)]
pub enum Error {
    /// The encoding of a secret key was malformed.
    #[error("Malformed secret key encoding.")]
    MalformedSecretKey,
    /// The encoding of a public key was malformed.
    #[error("Malformed public key encoding.")]
    MalformedPublicKey,
}
