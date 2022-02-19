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

/// A Schnorr signature on the Ristretto group.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Signature {
    pub(crate) r_bytes: [u8; 32],
    pub(crate) s_bytes: [u8; 32],
}

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Signature {
        let mut r_bytes = [0; 32];
        r_bytes.copy_from_slice(&bytes[0..32]);
        let mut s_bytes = [0; 32];
        s_bytes.copy_from_slice(&bytes[32..64]);
        Signature { r_bytes, s_bytes }
    }
}

impl From<Signature> for [u8; 64] {
    fn from(sig: Signature) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[0..32].copy_from_slice(&sig.r_bytes[..]);
        bytes[32..64].copy_from_slice(&sig.s_bytes[..]);
        bytes
    }
}

impl hex::FromHex for Signature {
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 64];

        match hex::decode_to_slice(hex, &mut bytes[..]) {
            Ok(()) => Ok(Self::from(bytes)),
            Err(_) => Err("invalid hex"),
        }
    }
}
