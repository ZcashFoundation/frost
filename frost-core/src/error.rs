//! FROST Error types

use thiserror::Error;

/// An error related to FROST.
#[non_exhaustive]
#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum Error {
    /// min_signers is invalid
    #[error("min_signers must be at least 2 and not larger than max_signers")]
    InvalidMinSigners,
    /// max_signers is invalid
    #[error("max_signers must be at least 2")]
    InvalidMaxSigners,
    /// max_signers is invalid
    #[error("coefficients must have min_signers-1 elements")]
    InvalidCoefficients,
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
    /// This element MUST have (large) prime order.
    #[error("Invalid for this element to not have large prime order.")]
    InvalidNonPrimeOrderElement,
    /// Duplicated shares provided
    #[error("Duplicated shares provided.")]
    DuplicatedShares,
    /// Commitment equals the identity
    #[error("Commitment equals the identity.")]
    IdentityCommitment,
    /// Signature share verification failed.
    #[error("Invalid signature share.")]
    InvalidSignatureShare {
        /// The identifier of the signer whose share validation failed,
        /// encoded as a byte vector with ciphersuite-dependent endianness
        /// (can be decoded with [`crate::frost::Identifier::deserialize`]).
        signer: Vec<u8>,
    },
    /// Secret share verification failed.
    #[error("Invalid secret share.")]
    InvalidSecretShare,
    /// Round 1 package not found for Round 2 participant.
    #[error("Round 1 package not found for Round 2 participant.")]
    PackageNotFound,
    /// Incorrect number of packages.
    #[error("Incorrect number of packages.")]
    IncorrectNumberOfPackages,
    /// The incorrect package was specified.
    #[error("The incorrect package was specified.")]
    IncorrectPackage,
    /// The ciphersuite does not support DKG.
    #[error("The ciphersuite does not support DKG.")]
    DKGNotSupported,
    /// The proof of knowledge is not valid.
    #[error("The proof of knowledge is not valid.")]
    InvalidProofOfKnowledge,
}
