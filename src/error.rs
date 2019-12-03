use thiserror::Error;

/// An error related to RedJubJub signatures.
#[derive(Error, Debug)]
pub enum Error {
    /// This is a stub variant to check that thiserror derive works.
    #[error("Stub error--  remove this.")]
    StubError,
}
