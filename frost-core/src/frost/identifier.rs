//! FROST participant identifiers

use std::{
    fmt::{self, Debug},
    hash::{Hash, Hasher},
    marker::PhantomData,
};

use crate::{Ciphersuite, Error, Field, Group, Scalar};

/// A FROST participant identifier.
///
/// The identifier is a field element in the scalar field that the secret polynomial is defined
/// over, corresponding to some x-coordinate for a polynomial f(x) = y.  MUST NOT be zero in the
/// field, as f(0) = the shared secret.
#[derive(Copy, Clone)]
pub struct Identifier<C>(u16, PhantomData<C>);

impl<C> Identifier<C>
where
    C: Ciphersuite,
{
    // Convert the identifier to a Scalar.
    pub(crate) fn to_scalar(self) -> Scalar<C> {
        // Classic left-to-right double-and-add algorithm that skips the first bit 1 (since
        // identifiers are never zero, there is always a bit 1), thus `sum` starts with 1 too.
        let one = <<C::Group as Group>::Field as Field>::one();
        let mut sum = <<C::Group as Group>::Field as Field>::one();
        let bits = (self.0.to_be_bytes().len() as u32) * 8;
        for i in (0..(bits - self.0.leading_zeros() - 1)).rev() {
            sum = sum + sum;
            if self.0 & (1 << i) != 0 {
                sum = sum + one;
            }
        }
        sum
    }
}

impl<C> PartialEq for Identifier<C> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<C> Eq for Identifier<C> {}

impl<C> PartialOrd for Identifier<C> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<C> Ord for Identifier<C> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<C> Debug for Identifier<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Identifier").field(&self.0).finish()
    }
}

impl<C> Hash for Identifier<C>
where
    C: Ciphersuite,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl<C> From<Identifier<C>> for u16
where
    C: Ciphersuite,
{
    fn from(identifier: Identifier<C>) -> Self {
        identifier.0
    }
}

impl<C> TryFrom<u16> for Identifier<C>
where
    C: Ciphersuite,
{
    type Error = Error;

    fn try_from(n: u16) -> Result<Identifier<C>, Self::Error> {
        if n == 0 {
            Err(Self::Error::InvalidZeroScalar)
        } else {
            Ok(Self(n, Default::default()))
        }
    }
}
