//! Schnorr signatures over prime order groups (or subgroups)

use std::fmt::Debug;

use crate::{Ciphersuite, Group};

/// A Schnorr signature over some prime order group (or subgroup).
pub trait Signature<C: Ciphersuite>: Copy + Clone + Debug + Eq + PartialEq {
    /// Get the scalar `z` component of a Schnorr signature.
    ///
    /// This function MUST check the validity of the deserialization of a scalar field element as [`DeserializeScalar()`] from the spec.
    ///
    /// [`DeserializeScalar()`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.html#section-3.1-3.8
    fn z(&self) -> <C::Group as Group>::Scalar;

    /// Get the group element `R` component of a Schnorr signature.
    ///
    /// This function MUST check the validity of the deserialization of a group element as
    /// [`DeserializeElement()`] from the spec, including rejecting the identity element of the
    /// group.
    ///
    /// [`DeserializeElement()`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.html#section-3.1-3.6
    fn R(&self) -> <C::Group as Group>::Element;

    /// Parse a Schnorr signature from its byte representation.
    ///
    /// This should be the same for both singleton and threshold signatures.
    fn from_bytes(bytes: &[u8]) -> Self;

    /// Serialize a signature to its byte representation.
    ///
    /// This should be the same for both singleton and threshold signatures.
    fn to_bytes(&self) -> &[u8];
}
