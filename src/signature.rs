use std::{convert, fmt};

/// A RedJubJub signature.
pub struct Signature(pub [u8; 64]);

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Signature {
        Signature(bytes)
    }
}

impl From<Signature> for [u8; 64] {
    fn from(s: Signature) -> [u8; 64] {
        s.0
    }
}

// These impls all only exist because of array length restrictions.

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Signature").field(&self.0[..]).finish()
    }
}

impl Copy for Signature {}

impl Clone for Signature {
    fn clone(&self) -> Self {
        let mut bytes = [0; 64];
        bytes[..].copy_from_slice(&self.0[..]);
        Self(bytes)
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Eq for Signature {}
