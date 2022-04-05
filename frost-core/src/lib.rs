#![allow(non_snake_case)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

pub mod batch;
mod error;
pub mod frost;
pub(crate) mod signature;
mod signing_key;
mod verifying_key;

pub use error::Error;
pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verifying_key::VerifyingKey;

/// A prime-order group (or subgroup) that provides everything we need to create and verify Schnorr
/// signatures.
///
/// This trait does not have to be implemented for the curve/element/point itself, it can be a
/// pass-through, implemented for a type just for the ciphersuite, and calls through to another
/// implementation underneath, so that this trait does not have to be implemented for types you
/// don't own.
pub trait Group {
    /// An element of the scalar finite field that our group is defined over.
    type Scalar;

    /// An element of our group that we will be computing over.
    type Element: Mul<Self::Scalar, Output = Self::Element> + Sub<Output = Self::Element>;

    /// The order of the the quotient group when the prime order subgroup divides the order of the
    /// full group.
    ///
    /// If using a prime order elliptic curve, the cofactor should be 1 in the scalar field.
    const COFACTOR: Self::Scalar;

    /// Additive [identity] of the prime order group.
    ///
    /// [identity]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.html#section-3.1-3.2
    const IDENTITY: Self::Element;

    /// The fixed generator element of the prime order group.
    ///
    /// The 'base' of [`ScalarBaseMult()`] from the spec.
    /// [`ScalarBaseMult()`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.html#section-3.1
    const BASEPOINT: Self::Element;
}

/// A [FROST ciphersuite] specifies the underlying prime-order group details and cryptographic hash
/// function.
///
/// [FROST ciphersuite]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.html#name-ciphersuites
pub trait Ciphersuite {
    /// The prime order group (or subgroup) that this ciphersuite operates over.
    type Group: Group;

    /// H1 for a FROST ciphersuite.
    ///
    /// [spec]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash
    fn H1(m: &[u8]) -> &[u8];

    /// H2 for a FROST ciphersuite.
    ///
    /// [spec]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash
    fn H2(m: &[u8]) -> &[u8];

    /// H3 for a FROST ciphersuite.
    ///
    /// [spec]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash
    fn H3(m: &[u8]) -> &[u8];

    /// Generates the challenge as is required for Schnorr signatures.
    ///
    /// Deals in bytes, so that [FROST] and singleton signing and verification can use it with different
    /// types.
    ///
    /// This is the only invocation of the H2 hash function from the [RFC].
    ///
    /// [FROST]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.html#section-4.6
    /// [RFC]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-04.html#section-3.2
    fn challenge(
        R_bytes: &[u8; 32],
        pubkey_bytes: &[u8; 32],
        msg: &[u8],
    ) -> <Self::Group as Group>::Scalar;
}
