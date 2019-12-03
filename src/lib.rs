#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]

//! Docs require the `nightly` feature until RFC 1990 lands.

mod public_key;
mod secret_key;
mod signature;
mod error;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
