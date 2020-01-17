use std::{convert::TryFrom, marker::PhantomData};

use crate::{Error, Randomizer, Scalar, SigType, Signature, SpendAuth};

/// A refinement type for `[u8; 32]` indicating that the bytes represent
/// an encoding of a RedJubJub public key.
///
/// This is useful for representing a compressed public key; the
/// [`PublicKey`] type in this library holds other decompressed state
/// used in signature verification.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicKeyBytes<T: SigType> {
    pub(crate) bytes: [u8; 32],
    pub(crate) _marker: PhantomData<T>,
}

impl<T: SigType> From<[u8; 32]> for PublicKeyBytes<T> {
    fn from(bytes: [u8; 32]) -> PublicKeyBytes<T> {
        PublicKeyBytes {
            bytes,
            _marker: PhantomData,
        }
    }
}

impl<T: SigType> From<PublicKeyBytes<T>> for [u8; 32] {
    fn from(refined: PublicKeyBytes<T>) -> [u8; 32] {
        refined.bytes
    }
}

/// A valid RedJubJub public key.
///
/// This type holds decompressed state used in signature verification; if the
/// public key may not be used immediately, it is probably better to use
/// [`PublicKeyBytes`], which is a refinement type for `[u8; 32]`.
///
/// ## Consensus properties
///
/// The `TryFrom<PublicKeyBytes>` conversion performs the following Zcash
/// consensus rule checks:
///
/// 1. The check that the bytes are a canonical encoding of a public key;
/// 2. The check that the public key is not a point of small order.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "PublicKeyBytes<T>"))]
#[cfg_attr(feature = "serde", serde(into = "PublicKeyBytes<T>"))]
#[cfg_attr(feature = "serde", serde(bound = "T: SigType"))]
pub struct PublicKey<T: SigType> {
    // XXX-jubjub: this should just be Point
    pub(crate) point: jubjub::ExtendedPoint,
    pub(crate) bytes: PublicKeyBytes<T>,
}

impl<T: SigType> From<PublicKey<T>> for PublicKeyBytes<T> {
    fn from(pk: PublicKey<T>) -> PublicKeyBytes<T> {
        pk.bytes
    }
}

impl<T: SigType> From<PublicKey<T>> for [u8; 32] {
    fn from(pk: PublicKey<T>) -> [u8; 32] {
        pk.bytes.bytes
    }
}

impl<T: SigType> TryFrom<PublicKeyBytes<T>> for PublicKey<T> {
    type Error = Error;

    fn try_from(bytes: PublicKeyBytes<T>) -> Result<Self, Self::Error> {
        // XXX-jubjub: this should not use CtOption
        // XXX-jubjub: this takes ownership of bytes, while Fr doesn't.
        // This checks that the encoding is canonical...
        let maybe_point = jubjub::AffinePoint::from_bytes(bytes.bytes);
        if maybe_point.is_some().into() {
            let point: jubjub::ExtendedPoint = maybe_point.unwrap().into();
            // This checks that the public key is not of small order.
            if <bool>::from(point.is_small_order()) == false {
                Ok(PublicKey { point, bytes })
            } else {
                Err(Error::MalformedPublicKey)
            }
        } else {
            Err(Error::MalformedPublicKey)
        }
    }
}

impl<T: SigType> TryFrom<[u8; 32]> for PublicKey<T> {
    type Error = Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        use std::convert::TryInto;
        PublicKeyBytes::from(bytes).try_into()
    }
}

impl PublicKey<SpendAuth> {
    /// Randomize this public key with the given `randomizer`.
    ///
    /// Randomization is only supported for `SpendAuth` keys.
    pub fn randomize(&self, randomizer: &Randomizer) -> PublicKey<SpendAuth> {
        use crate::private::Sealed;
        let point = &self.point + &(&SpendAuth::basepoint() * randomizer);
        let bytes = PublicKeyBytes {
            bytes: jubjub::AffinePoint::from(&point).to_bytes(),
            _marker: PhantomData,
        };
        PublicKey { bytes, point }
    }
}

impl<T: SigType> PublicKey<T> {
    pub(crate) fn from_secret(s: &Scalar) -> PublicKey<T> {
        let point = &T::basepoint() * s;
        let bytes = PublicKeyBytes {
            bytes: jubjub::AffinePoint::from(&point).to_bytes(),
            _marker: PhantomData,
        };
        PublicKey { bytes, point }
    }

    /// Verify a purported `signature` over `msg` made by this public key.
    // This is similar to impl signature::Verifier but without boxed errors
    pub fn verify(&self, msg: &[u8], signature: &Signature<T>) -> Result<(), Error> {
        #![allow(non_snake_case)]
        use crate::HStar;

        let r = {
            // XXX-jubjub: should not use CtOption here
            // XXX-jubjub: inconsistent ownership in from_bytes
            let maybe_point = jubjub::AffinePoint::from_bytes(signature.r_bytes);
            if maybe_point.is_some().into() {
                jubjub::ExtendedPoint::from(maybe_point.unwrap())
            } else {
                return Err(Error::InvalidSignature);
            }
        };

        let s = {
            // XXX-jubjub: should not use CtOption here
            let maybe_scalar = Scalar::from_bytes(&signature.s_bytes);
            if maybe_scalar.is_some().into() {
                maybe_scalar.unwrap()
            } else {
                return Err(Error::InvalidSignature);
            }
        };

        let c = HStar::default()
            .update(&signature.r_bytes[..])
            .update(&self.bytes.bytes[..]) // XXX ugly
            .update(msg)
            .finalize();

        // XXX rewrite as normal double scalar mul
        // Verify check is h * ( - s * B + R  + c * A) == 0
        //                 h * ( s * B - c * A - R) == 0
        let sB = &T::basepoint() * &s;
        let cA = &self.point * &c;
        let check = sB - cA - r;

        if check.is_small_order().into() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
