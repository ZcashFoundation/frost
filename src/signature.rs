use std::{marker::PhantomData, convert, fmt};

use crate::SigType;

/// A RedJubJub signature.
pub struct Signature<T: SigType> {
    bytes: [u8; 64],
    _marker: PhantomData<T>,
}

impl<T: SigType> From<[u8; 64]> for Signature<T> {
    fn from(bytes: [u8; 64]) -> Signature<T> {
        Signature {
            bytes, _marker: PhantomData,
        }
    }
}

impl<T: SigType> From<Signature<T>> for [u8; 64] {
    fn from(s: Signature<T>) -> [u8; 64] {
        s.bytes
    }
}

// These impls all only exist because of array length restrictions.

// XXX print the type variable
impl<T: SigType> fmt::Debug for Signature<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        //f.debug_tuple("Signature").field(&self.0[..]).finish()
        f.debug_tuple("Signature").finish()
    }
}

impl<T: SigType> Copy for Signature<T> {}

impl<T: SigType> Clone for Signature<T> {
    fn clone(&self) -> Self {
        let mut bytes = [0; 64];
        bytes[..].copy_from_slice(&self.bytes[..]);
        Signature {
            bytes, _marker: PhantomData,
        }
    }
}

impl<T: SigType> PartialEq for Signature<T> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

impl<T: SigType> Eq for Signature<T> {}
