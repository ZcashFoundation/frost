//! FROST participant identifiers

use std::{
    fmt::{self, Debug},
    hash::{Hash, Hasher},
    ops::Index,
};

use crate::{Ciphersuite, Error, Field, Group, Scalar};

/// A FROST participant identifier.
///
/// The identifier is a field element in the scalar field that the secret polynomial is defined
/// over, corresponding to some x-coordinate for a polynomial f(x) = y.  MUST NOT be zero in the
/// field, as f(0) = the shared secret.
#[derive(Copy, Clone)]
pub struct Identifier<C: Ciphersuite>(pub(crate) Scalar<C>);

impl<C> Debug for Identifier<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Identifier")
            .field(&usize::from(*self))
            .finish()
    }
}

impl<C> Eq for Identifier<C> where C: Ciphersuite {}

impl<C> From<Identifier<C>> for u16
where
    C: Ciphersuite,
{
    fn from(id: Identifier<C>) -> u16 {
        let mut bytes = [0u8; 2];

        let serialized = <<C::Group as Group>::Field as Field>::serialize(&id.0);

        bytes.copy_from_slice(&serialized.as_ref()[..2]);

        u16::from_le_bytes(bytes)
    }
}

impl<C> From<Identifier<C>> for usize
where
    C: Ciphersuite,
{
    // TODO: this feels janky, are we confident we aren't clamping off the higher byte values?
    fn from(id: Identifier<C>) -> usize {
        // This is 8 bytes because usize is up to 8 bytes depending on the platform.
        //
        // https://doc.rust-lang.org/stable/std/primitive.usize.html#method.from_le_bytes
        let mut bytes = [0u8; 8];

        let serialized = <<C::Group as Group>::Field as Field>::serialize(&id.0);

        bytes.copy_from_slice(&serialized.as_ref()[..8]);

        usize::from_le_bytes(bytes)
    }
}

impl<C> Hash for Identifier<C>
where
    C: Ciphersuite,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        <<C::Group as Group>::Field as Field>::serialize(&self.0)
            .as_ref()
            .hash(state)
    }
}

impl<C, T> Index<Identifier<C>> for Vec<T>
where
    C: Ciphersuite,
{
    type Output = T;

    fn index(&self, id: Identifier<C>) -> &Self::Output {
        &self[usize::from(id)]
    }
}

impl<C> std::ops::Mul<Scalar<C>> for Identifier<C>
where
    C: Ciphersuite,
{
    type Output = Scalar<C>;

    fn mul(self, scalar: Scalar<C>) -> Scalar<C> {
        self.0 * scalar
    }
}

impl<C> std::ops::MulAssign<Identifier<C>> for Scalar<C>
where
    C: Ciphersuite,
{
    fn mul_assign(&mut self, identifier: Identifier<C>) {
        *self = *self * identifier.0
    }
}

impl<C> Ord for Identifier<C>
where
    C: Ciphersuite,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        u16::from(*self).cmp(&u16::from(*other))
    }
}

impl<C> PartialEq for Identifier<C>
where
    C: Ciphersuite,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<C> PartialOrd for Identifier<C>
where
    C: Ciphersuite,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        u16::from(*self).partial_cmp(&u16::from(*other))
    }
}

impl<C> std::ops::Sub for Identifier<C>
where
    C: Ciphersuite,
{
    type Output = Self;

    fn sub(self, rhs: Identifier<C>) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<C> TryFrom<u16> for Identifier<C>
where
    C: Ciphersuite,
{
    type Error = Error;

    // TODO: this feels like a cluster. Improve?
    fn try_from(n: u16) -> Result<Identifier<C>, Self::Error> {
        let mut bytes =
            Vec::from(<<C::Group as Group>::Field as Field>::Serialization::default().as_ref());

        for (i, byte) in n.to_le_bytes().iter().enumerate() {
            bytes[i] = *byte;
        }

        let serialization = bytes
            .try_into()
            .map_err(|_| Self::Error::MalformedIdentifier)?;

        let scalar = <<C::Group as Group>::Field as Field>::deserialize(&serialization)?;

        // Participant identifiers are public, so this comparison doesn't need to be constant-time.
        if scalar == <<C::Group as Group>::Field as Field>::zero() {
            Err(Self::Error::InvalidZeroScalar)
        } else {
            Ok(Self(scalar))
        }
    }
}
