#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![deny(missing_docs)]

//! Docs require the `nightly` feature until RFC 1990 lands.

mod constants;
mod error;
mod public_key;
mod secret_key;
mod signature;

/// An element of the JubJub scalar field used for randomization of public and secret keys.
pub type Randomizer = jubjub::Fr;

pub use error::Error;
pub use public_key::{PublicKey, PublicKeyBytes};
pub use secret_key::{SecretKey, SecretKeyBytes};
pub use signature::Signature;

/// Abstracts over different RedJubJub parameter choices.
///
/// As described [at the end of §5.4.6][concretereddsa] of the Zcash
/// protocol specification, the generator used in RedJubjub is left as
/// an unspecified parameter, chosen differently for each of
/// `BindingSig` and `SpendAuthSig`.
///
/// To handle this, we encode the parameter choice as a genuine type
/// parameter.
///
/// [concretereddsa]: https://zips.z.cash/protocol/protocol.pdf#concretereddsa
pub trait SigType: private::Sealed {}

/// A type variable corresponding to Zcash's `BindingSig`.
pub struct Binding {}
impl SigType for Binding {}

/// A type variable corresponding to Zcash's `SpendAuthSig`.
pub struct SpendAuth {}
impl SigType for SpendAuth {}

mod private {
    use super::*;
    pub trait Sealed {}
    impl Sealed for Binding {}
    impl Sealed for SpendAuth {}
}
