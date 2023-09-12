#![allow(non_snake_case)]
// It's emitting false positives; see https://github.com/rust-lang/rust-clippy/issues/9413
#![allow(clippy::derive_partial_eq_without_eq)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc = document_features::document_features!()]

use std::{
    default::Default,
    fmt::Debug,
    ops::{Add, Mul, Sub},
};

use rand_core::{CryptoRng, RngCore};

// Re-export serde
#[cfg(feature = "serde")]
pub use serde;

pub mod batch;
#[cfg(any(test, feature = "test-impl"))]
pub mod benches;
mod error;
pub mod frost;
mod scalar_mul;
mod signature;
mod signing_key;
#[cfg(any(test, feature = "test-impl"))]
pub mod tests;
mod verifying_key;

pub use error::{Error, FieldError, GroupError};
pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verifying_key::VerifyingKey;

/// A prime order finite field GF(q) over which all scalar values for our prime order group can be
/// multiplied are defined.
///
/// This trait does not have to be implemented for a finite field scalar itself, it can be a
/// pass-through, implemented for a type just for the ciphersuite, and calls through to another
/// implementation underneath, so that this trait does not have to be implemented for types you
/// don't own.
pub trait Field: Copy + Clone {
    /// An element of the scalar field GF(p).
    /// The Eq/PartialEq implementation MUST be constant-time.
    type Scalar: Add<Output = Self::Scalar>
        + Copy
        + Clone
        + Eq
        + Mul<Output = Self::Scalar>
        + PartialEq
        + Sub<Output = Self::Scalar>;

    /// A unique byte array buf of fixed length N.
    type Serialization: AsRef<[u8]> + Debug + TryFrom<Vec<u8>>;

    /// Returns the zero element of the field, the additive identity.
    fn zero() -> Self::Scalar;

    /// Returns the one element of the field, the multiplicative identity.
    fn one() -> Self::Scalar;

    /// Computes the multiplicative inverse of an element of the scalar field, failing if the
    /// element is zero.
    fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, FieldError>;

    /// Generate a random scalar from the entire space [0, l-1]
    ///
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-3.1-3.3>
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar;

    /// A member function of a [`Field`] that maps a [`Scalar`] to a unique byte array buf of
    /// fixed length Ne.
    ///
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-3.1-3.8>
    fn serialize(scalar: &Self::Scalar) -> Self::Serialization;

    /// A member function of a [`Field`] that maps a [`Scalar`] to a unique byte array buf of
    /// fixed length Ne, in little-endian order.
    ///
    /// This is used internally.
    fn little_endian_serialize(scalar: &Self::Scalar) -> Self::Serialization;

    /// A member function of a [`Field`] that attempts to map a byte array `buf` to a [`Scalar`].
    ///
    /// Fails if the input is not a valid byte representation of an [`Scalar`] of the
    /// [`Field`]. This function can raise an [`Error`] if deserialization fails.
    ///
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-3.1-3.9>
    fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, FieldError>;
}

/// An element of the [`Ciphersuite`] `C`'s [`Group`]'s scalar [`Field`].
pub type Scalar<C> = <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar;

#[cfg(feature = "serde")]
#[cfg_attr(feature = "internals", visibility::make(pub))]
#[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
/// Helper struct to serialize a Scalar.
pub(crate) struct ScalarSerialization<C: Ciphersuite>(
    pub <<<C as Ciphersuite>::Group as Group>::Field as Field>::Serialization,
);

#[cfg(feature = "serde")]
impl<C> serde::Serialize for ScalarSerialization<C>
where
    C: Ciphersuite,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serdect::array::serialize_hex_lower_or_bin(&self.0.as_ref(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, C> serde::Deserialize<'de> for ScalarSerialization<C>
where
    C: Ciphersuite,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Get size from the size of the zero scalar
        let zero = <<C::Group as Group>::Field as Field>::zero();
        let len = <<C::Group as Group>::Field as Field>::serialize(&zero)
            .as_ref()
            .len();

        let mut bytes = vec![0u8; len];
        serdect::array::deserialize_hex_or_bin(&mut bytes[..], deserializer)?;
        let array = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid byte length"))?;
        Ok(Self(array))
    }
}

/// A prime-order group (or subgroup) that provides everything we need to create and verify Schnorr
/// signatures.
///
/// This trait does not have to be implemented for the curve/element/point itself, it can be a
/// pass-through, implemented for a type just for the ciphersuite, and calls through to another
/// implementation underneath, so that this trait does not have to be implemented for types you
/// don't own.
pub trait Group: Copy + Clone + PartialEq {
    /// A prime order finite field GF(q) over which all scalar values for our prime order group can
    /// be multiplied are defined.
    type Field: Field;

    /// An element of our group that we will be computing over.
    type Element: Add<Output = Self::Element>
        + Copy
        + Clone
        + Eq
        + Mul<<Self::Field as Field>::Scalar, Output = Self::Element>
        + PartialEq
        + Sub<Output = Self::Element>;

    /// A unique byte array buf of fixed length N.
    ///
    /// Little-endian!
    type Serialization: AsRef<[u8]> + Debug + TryFrom<Vec<u8>>;

    /// The order of the the quotient group when the prime order subgroup divides the order of the
    /// full curve group.
    ///
    /// If using a prime order elliptic curve, the cofactor should be 1 in the scalar field.
    fn cofactor() -> <Self::Field as Field>::Scalar;

    /// Additive [identity] of the prime order group.
    ///
    /// [identity]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-3.1-3.2
    fn identity() -> Self::Element;

    /// The fixed generator element of the prime order group.
    ///
    /// The 'base' of ['ScalarBaseMult()'] from the spec.
    ///
    /// [`ScalarBaseMult()`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-3.1-3.5
    fn generator() -> Self::Element;

    /// A member function of a group _G_ that maps an [`Element`] to a unique byte array buf of
    /// fixed length Ne.
    ///
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-3.1-3.6>
    fn serialize(element: &Self::Element) -> Self::Serialization;

    /// A member function of a [`Group`] that attempts to map a byte array `buf` to an [`Element`].
    ///
    /// Fails if the input is not a valid byte representation of an [`Element`] of the
    /// [`Group`]. This function can raise an [`Error`] if deserialization fails or if the
    /// resulting [`Element`] is the identity element of the group
    ///
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-3.1-3.7>
    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, GroupError>;
}

/// An element of the [`Ciphersuite`] `C`'s [`Group`].
pub type Element<C> = <<C as Ciphersuite>::Group as Group>::Element;

#[cfg(feature = "serde")]
pub(crate) struct ElementSerialization<C: Ciphersuite>(
    <<C as Ciphersuite>::Group as Group>::Serialization,
);

#[cfg(feature = "serde")]
impl<C> serde::Serialize for ElementSerialization<C>
where
    C: Ciphersuite,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serdect::array::serialize_hex_lower_or_bin(&self.0.as_ref(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, C> serde::Deserialize<'de> for ElementSerialization<C>
where
    C: Ciphersuite,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Get size from the size of the generator
        let generator = <C::Group>::generator();
        let len = <C::Group>::serialize(&generator).as_ref().len();

        let mut bytes = vec![0u8; len];
        serdect::array::deserialize_hex_or_bin(&mut bytes[..], deserializer)?;
        let array = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid byte length"))?;
        Ok(Self(array))
    }
}

/// A [FROST ciphersuite] specifies the underlying prime-order group details and cryptographic hash
/// function.
///
/// [FROST ciphersuite]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-ciphersuites
pub trait Ciphersuite: Copy + Clone + PartialEq + Debug {
    /// The ciphersuite ID string
    const ID: &'static str;

    /// The prime order group (or subgroup) that this ciphersuite operates over.
    type Group: Group;

    /// A unique byte array of fixed length.
    type HashOutput: AsRef<[u8]>;

    /// A unique byte array of fixed length that is the `Group::ElementSerialization` +
    /// `Group::ScalarSerialization`
    type SignatureSerialization: AsRef<[u8]> + TryFrom<Vec<u8>>;

    /// [H1] for a FROST ciphersuite.
    ///
    /// Maps arbitrary inputs to `Self::Scalar` elements of the prime-order group scalar field.
    ///
    /// [H1]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-cryptographic-hash-function
    fn H1(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar;

    /// [H2] for a FROST ciphersuite.
    ///
    /// Maps arbitrary inputs to `Self::Scalar` elements of the prime-order group scalar field.
    ///
    /// [H2]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-cryptographic-hash-function
    fn H2(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar;

    /// [H3] for a FROST ciphersuite.
    ///
    /// Maps arbitrary inputs to `Self::Scalar` elements of the prime-order group scalar field.
    ///
    /// [H3]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-cryptographic-hash-function
    fn H3(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar;

    /// [H4] for a FROST ciphersuite.
    ///
    /// Usually an an alias for the ciphersuite hash function _H_ with domain separation applied.
    ///
    /// [H4]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-cryptographic-hash-function
    fn H4(m: &[u8]) -> Self::HashOutput;

    /// [H5] for a FROST ciphersuite.
    ///
    /// Usually an an alias for the ciphersuite hash function _H_ with domain separation applied.
    ///
    /// [H5]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#cryptographic-hash
    fn H5(m: &[u8]) -> Self::HashOutput;

    /// Hash function for a FROST ciphersuite, used for the DKG.
    ///
    /// The DKG it not part of the specification, thus this is optional.
    /// It can return None if DKG is not supported by the Ciphersuite. This is
    /// the default implementation.
    ///
    /// Maps arbitrary inputs to non-zero `Self::Scalar` elements of the prime-order group scalar field.
    fn HDKG(_m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        None
    }

    /// Hash function for a FROST ciphersuite, used for deriving identifiers from strings.
    ///
    /// This feature is not part of the specification and is just a convenient
    /// way of creating identifiers. Therefore it can return None if this is not supported by the
    /// Ciphersuite. This is the default implementation.
    ///
    /// Maps arbitrary inputs to non-zero `Self::Scalar` elements of the prime-order group scalar field.
    fn HID(_m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        None
    }

    /// Verify a signature for this ciphersuite. The default implementation uses the "cofactored"
    /// equation (it multiplies by the cofactor returned by [`Group::cofactor()`]).
    ///
    /// # Cryptographic Safety
    ///
    /// You may override this to provide a tailored implementation, but if the ciphersuite defines it,
    /// it must also multiply by the cofactor to comply with the RFC. Note that batch verification
    /// (see [`crate::batch::Verifier`]) also uses the default implementation regardless whether a
    /// tailored implementation was provided.
    fn verify_signature(
        msg: &[u8],
        signature: &Signature<Self>,
        public_key: &VerifyingKey<Self>,
    ) -> Result<(), Error<Self>> {
        let c = crate::challenge::<Self>(&signature.R, &public_key.element, msg);

        public_key.verify_prehashed(c, signature)
    }
}

// The short 4-byte ID. Derived as the CRC-32 of the UTF-8
// encoded ID in big endian format.
const fn short_id<C>() -> [u8; 4]
where
    C: Ciphersuite,
{
    const_crc32::crc32(C::ID.as_bytes()).to_be_bytes()
}

/// A type refinement for the scalar field element representing the per-message _[challenge]_.
///
/// [challenge]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-signature-challenge-computa
#[derive(Clone)]
pub struct Challenge<C: Ciphersuite>(pub(crate) <<C::Group as Group>::Field as Field>::Scalar);

impl<C> Challenge<C>
where
    C: Ciphersuite,
{
    /// Creates a challenge from a scalar.
    #[cfg(feature = "internals")]
    pub fn from_scalar(
        scalar: <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar,
    ) -> Self {
        Self(scalar)
    }

    /// Return the underlying scalar.
    #[cfg(feature = "internals")]
    pub fn to_scalar(self) -> <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar {
        self.0
    }
}

impl<C> Debug for Challenge<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Secret")
            .field(&hex::encode(<<C::Group as Group>::Field>::serialize(
                &self.0,
            )))
            .finish()
    }
}

/// Generates the challenge as is required for Schnorr signatures.
///
/// Deals in bytes, so that [FROST] and singleton signing and verification can use it with different
/// types.
///
/// This is the only invocation of the H2 hash function from the [RFC].
///
/// [FROST]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-signature-challenge-computa
/// [RFC]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#section-3.2
#[cfg_attr(feature = "internals", visibility::make(pub))]
#[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
fn challenge<C>(R: &Element<C>, verifying_key: &Element<C>, msg: &[u8]) -> Challenge<C>
where
    C: Ciphersuite,
{
    let mut preimage = vec![];

    preimage.extend_from_slice(<C::Group>::serialize(R).as_ref());
    preimage.extend_from_slice(<C::Group>::serialize(verifying_key).as_ref());
    preimage.extend_from_slice(msg);

    Challenge(C::H2(&preimage[..]))
}

/// Generates a random nonzero scalar.
///
/// It assumes that the Scalar Eq/PartialEq implementation is constant-time.
pub(crate) fn random_nonzero<C: Ciphersuite, R: RngCore + CryptoRng>(rng: &mut R) -> Scalar<C> {
    loop {
        let scalar = <<C::Group as Group>::Field>::random(rng);

        if scalar != <<C::Group as Group>::Field>::zero() {
            return scalar;
        }
    }
}

/// Serialize a placeholder ciphersuite field with the ciphersuite ID string.
#[cfg(feature = "serde")]
pub(crate) fn ciphersuite_serialize<S, C>(_: &(), s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    C: Ciphersuite,
{
    use serde::Serialize;

    if s.is_human_readable() {
        C::ID.serialize(s)
    } else {
        serde::Serialize::serialize(&short_id::<C>(), s)
    }
}

/// Deserialize a placeholder ciphersuite field, checking if it's the ciphersuite ID string.
#[cfg(feature = "serde")]
pub(crate) fn ciphersuite_deserialize<'de, D, C>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
    C: Ciphersuite,
{
    if deserializer.is_human_readable() {
        let s: &str = serde::de::Deserialize::deserialize(deserializer)?;
        if s != C::ID {
            Err(serde::de::Error::custom("wrong ciphersuite"))
        } else {
            Ok(())
        }
    } else {
        let buffer: [u8; 4] = serde::de::Deserialize::deserialize(deserializer)?;
        if buffer != short_id::<C>() {
            Err(serde::de::Error::custom("wrong ciphersuite"))
        } else {
            Ok(())
        }
    }
}

// Default byte-oriented serialization for structs that need to be communicated.
//
// Note that we still manually implement these methods in each applicable type,
// instead of making these traits `pub` and asking users to import the traits.
// The reason is that ciphersuite traits would need to re-export these traits,
// parametrized with the ciphersuite, but trait aliases are not currently
// supported: <https://github.com/rust-lang/rust/issues/41517>

#[cfg(feature = "serialization")]
trait Serialize<C: Ciphersuite> {
    /// Serialize the struct into a Vec.
    fn serialize(&self) -> Result<Vec<u8>, Error<C>>;
}

#[cfg(feature = "serialization")]
trait Deserialize<C: Ciphersuite> {
    /// Deserialize the struct from a slice of bytes.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error<C>>
    where
        Self: std::marker::Sized;
}

#[cfg(feature = "serialization")]
impl<T: serde::Serialize, C: Ciphersuite> Serialize<C> for T {
    fn serialize(&self) -> Result<Vec<u8>, Error<C>> {
        postcard::to_stdvec(self).map_err(|_| Error::SerializationError)
    }
}

#[cfg(feature = "serialization")]
impl<T: for<'de> serde::Deserialize<'de>, C: Ciphersuite> Deserialize<C> for T {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error<C>> {
        postcard::from_bytes(bytes).map_err(|_| Error::DeserializationError)
    }
}
