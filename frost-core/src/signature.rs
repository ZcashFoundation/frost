// -*- mode: rust; -*-
//
// This file is part of frost-ristretto.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Henry de Valence <hdevalence@hdevalence.ca>
// - Deirdre Connolly <durumcrustulum@gmail.com>

//! Schnorr signatures on the Ristretto group

use std::fmt::Debug;

/// A Schnorr signature over some prime order group (or subgroup).
pub trait Signature: Copy + Clone + Debug + Eq + PartialEq {
    /// Parse a Schnorr signature from its byte representation.
    ///
    /// This should be the same for both singleton and threshold signatures.
    fn from_bytes(bytes: &[u8]) -> Self;

    /// Serialize a signature to its byte representation.
    ///
    /// This should be the same for both singleton and threshold signatures.
    fn to_bytes(&self) -> &[u8];
}
