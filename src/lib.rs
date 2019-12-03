#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![deny(missing_docs)]

//! Docs require the `nightly` feature until RFC 1990 lands.

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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
