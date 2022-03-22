// -*- mode: rust; -*-
//
// This file is part of frost-ristretto255.
// Copyright (c) 2020-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Chelsea H. Komlo <me@chelseakomlo.com>
// - Deirdre Connolly <deirdre@zfnd.org>
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! An implementation of FROST (Flexible Round-Optimized Schnorr Threshold)
//! signatures.
//!
//! If you are interested in deploying FROST, please do not hesitate to consult the FROST authors.
//!
//! This implementation currently only supports key generation using a central
//! dealer. In the future, we will add support for key generation via a DKG,
//! as specified in the FROST paper.
//!
//! Internally, keygen_with_dealer generates keys using Verifiable Secret
//! Sharing, where shares are generated using Shamir Secret Sharing.

use std::{convert::TryFrom, fmt::Debug};

use curve25519_dalek::scalar::Scalar;
use hex::FromHex;

pub mod keys;
pub mod round1;
pub mod round2;

#[cfg(test)]
mod tests;

use crate::{generate_challenge, Signature, H1};

/// The binding factor, also known as _rho_ (ρ)
///
/// Ensures each signature share is strongly bound to a signing set, specific set
/// of commitments, and a specific message.
///
/// <https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md>
#[derive(Clone, Debug, PartialEq)]
struct Rho(Scalar);

impl From<&round2::SigningPackage> for Rho {
    fn from(signing_package: &round2::SigningPackage) -> Rho {
        let preimage = signing_package.rho_preimage();

        let binding_factor = H1(&preimage[..]);

        Rho(Scalar::from_bytes_mod_order_wide(&binding_factor))
    }
}

impl FromHex for Rho {
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 32];

        match hex::decode_to_slice(hex, &mut bytes[..]) {
            Ok(()) => Self::try_from(bytes),
            Err(_) => Err("invalid hex"),
        }
    }
}

impl TryFrom<[u8; 32]> for Rho {
    type Error = &'static str;

    fn try_from(source: [u8; 32]) -> Result<Self, &'static str> {
        match Scalar::from_canonical_bytes(source) {
            Some(scalar) => Ok(Self(scalar)),
            None => Err("scalar was not canonically encoded"),
        }
    }
}

/// Generates the lagrange coefficient for the i'th participant.
fn generate_lagrange_coeff(
    signer_index: u16,
    signing_package: &round2::SigningPackage,
) -> Result<Scalar, &'static str> {
    let mut num = Scalar::one();
    let mut den = Scalar::one();

    // Ala the sorting of B, just always sort by index in ascending order
    //
    // https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#encoding-operations-dep-encoding
    for commitment in signing_package.signing_commitments() {
        if commitment.index == signer_index {
            continue;
        }
        num *= Scalar::from(commitment.index as u16);
        den *= Scalar::from(commitment.index as u16) - Scalar::from(signer_index as u16);
    }

    if den == Scalar::zero() {
        return Err("Duplicate shares provided");
    }

    // TODO: handle this unwrap better like other CtOption's
    let lagrange_coeff = num * den.invert();

    Ok(lagrange_coeff)
}

////////////////////////////////////////////////////////////////////////////////
// Aggregation
////////////////////////////////////////////////////////////////////////////////

/// Verifies each participant's signature share, and if all are valid,
/// aggregates the shares into a signature to publish.
///
/// Resulting signature is compatible with verification of a plain SpendAuth
/// signature.
///
/// This operation is performed by a coordinator that can communicate with all
/// the signing participants before publishing the final signature. The
/// coordinator can be one of the participants or a semi-trusted third party
/// (who is trusted to not perform denial of service attacks, but does not learn
/// any secret information). Note that because the coordinator is trusted to
/// report misbehaving parties in order to avoid publishing an invalid
/// signature, if the coordinator themselves is a signer and misbehaves, they
/// can avoid that step. However, at worst, this results in a denial of
/// service attack due to publishing an invalid signature.
pub fn aggregate(
    signing_package: &round2::SigningPackage,
    signing_shares: &[round2::SignatureShare],
    pubkeys: &keys::PublicKeyPackage,
) -> Result<Signature, &'static str> {
    let group_commitment = round2::GroupCommitment::try_from(signing_package)?;

    let challenge = generate_challenge(
        &group_commitment.0.compress().to_bytes(),
        &pubkeys.group_public.bytes.bytes,
        signing_package.message().as_slice(),
    );

    let rho: Rho = signing_package.into();

    // Verify the signature shares
    for signing_share in signing_shares {
        let signer_pubkey = pubkeys.signer_pubkeys.get(&signing_share.index).unwrap();
        let lambda_i = generate_lagrange_coeff(signing_share.index, signing_package)?;

        let R_share = signing_package
            .signing_commitment(&signing_share.index)
            .to_group_commitment_share(&rho);

        signing_share.verify(R_share, signer_pubkey, lambda_i, challenge)?;
    }

    // The aggregation of the signature shares by summing them up, resulting in
    // a plain Schnorr signature.
    let mut z = Scalar::zero();

    for signature_share in signing_shares {
        z += signature_share.signature.z_share;
    }

    Ok(Signature {
        R_bytes: group_commitment.0.compress().to_bytes(),
        z_bytes: z.to_bytes(),
    })
}
