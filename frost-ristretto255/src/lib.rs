// -*- mode: rust; -*-
//
// This file is part of redjubjub.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Deirdre Connolly <deirdre@zfnd.org>
// - Henry de Valence <hdevalence@hdevalence.ca>

#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod batch;
mod error;
pub mod frost;
mod messages;
pub(crate) mod signature;
mod signing_key;
mod verification_key;

pub use error::Error;
pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};
