//! Randomized FROST support.
//!
#![allow(non_snake_case)]

#[cfg(any(test, feature = "test-impl"))]
pub mod tests;

pub use frost_core;

use frost_core::{
    frost::{self, keys::PublicKeyPackage},
    Ciphersuite, Error, Field, Group, VerifyingKey,
};

use rand_core::{CryptoRng, RngCore};

/// Performed once by each participant selected for the signing operation.
///
/// Implements [`sign`] from the spec.
///
/// Receives the message to be signed and a set of signing commitments and a set
/// of randomizing commitments to be used in that signing operation, including
/// that for this participant.
///
/// Assumes the participant has already determined which nonce corresponds with
/// the commitment that was assigned by the coordinator in the SigningPackage.
///
/// [`sign`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-10.html#name-round-two-signature-share-g
pub fn sign<C: Ciphersuite>(
    signing_package: &frost::SigningPackage<C>,
    signer_nonces: &frost::round1::SigningNonces<C>,
    key_package: &frost::keys::KeyPackage<C>,
    randomizer_point: &<C::Group as Group>::Element,
) -> Result<frost::round2::SignatureShare<C>, Error<C>> {
    let public_key = key_package.group_public.to_element() + *randomizer_point;

    // Encodes the signing commitment list produced in round one as part of generating [`Rho`], the
    // binding factor.
    let binding_factor_list = frost::compute_binding_factor_list(
        signing_package,
        <C::Group as Group>::serialize(randomizer_point).as_ref(),
    );

    let rho: frost::BindingFactor<C> = binding_factor_list[key_package.identifier].clone();

    // Compute the group commitment from signing commitments produced in round one.
    let group_commitment = frost::compute_group_commitment(signing_package, &binding_factor_list)?;

    // Compute Lagrange coefficient.
    let lambda_i = frost::derive_interpolating_value(key_package.identifier(), signing_package)?;

    // Compute the per-message challenge.
    let challenge = frost_core::challenge::<C>(
        &group_commitment.to_element(),
        &public_key,
        signing_package.message().as_slice(),
    );

    // Compute the Schnorr signature share.
    let signature_share = frost::round2::compute_signature_share(
        signer_nonces,
        rho,
        lambda_i,
        key_package,
        challenge,
    );

    Ok(signature_share)
}

/// Aggregates the shares into a verified signature to publish.
///
/// Resulting signature is compatible with verification of a plain SpendAuth
/// signature.
///
/// If the aggegated signature does not verify, each participant's signature share
/// is validated, to find the cheater(s). This approach is more efficient and secure
/// as we don't need to verify all shares if the aggregate signature is verifiable
/// under the public group key and message (which should be the common case).
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
pub fn aggregate<C>(
    signing_package: &frost::SigningPackage<C>,
    signature_shares: &[frost::round2::SignatureShare<C>],
    pubkeys: &frost::keys::PublicKeyPackage<C>,
    randomized_params: &RandomizedParams<C>,
) -> Result<frost_core::Signature<C>, Error<C>>
where
    C: Ciphersuite,
{
    let public_key = randomized_params.randomized_group_public_key();

    // Encodes the signing commitment list produced in round one as part of generating [`Rho`], the
    // binding factor.
    let binding_factor_list = frost::compute_binding_factor_list(
        signing_package,
        <C::Group as Group>::serialize(randomized_params.randomizer_point()).as_ref(),
    );

    // Compute the group commitment from signing commitments produced in round one.
    let group_commitment = frost::compute_group_commitment(signing_package, &binding_factor_list)?;

    // Compute the per-message challenge.
    let challenge = frost_core::challenge::<C>(
        &group_commitment.clone().to_element(),
        &public_key.to_element(),
        signing_package.message().as_slice(),
    );

    // The aggregation of the signature shares by summing them up, resulting in
    // a plain Schnorr signature.
    //
    // Implements [`aggregate`] from the spec.
    //
    // [`aggregate`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-12.html#section-5.3
    let mut z = <<C::Group as Group>::Field as Field>::zero();

    for signature_share in signature_shares {
        z = z + signature_share.signature.z_share;
    }

    z = z + challenge.clone().to_scalar() * randomized_params.randomizer;

    let signature = frost_core::Signature::new(group_commitment.to_element(), z);

    // Verify the aggregate signature
    let verification_result = public_key.verify(signing_package.message(), &signature);

    // Only if the verification of the aggregate signature failed; verify each share to find the cheater.
    // This approach is more efficient since we don't need to verify all shares
    // if the aggregate signature is valid (which should be the common case).
    if let Err(err) = verification_result {
        // Verify the signature shares.
        for signature_share in signature_shares {
            // Look up the public key for this signer, where `signer_pubkey` = _G.ScalarBaseMult(s[i])_,
            // and where s[i] is a secret share of the constant term of _f_, the secret polynomial.
            let signer_pubkey = pubkeys
                .signer_pubkeys
                .get(&signature_share.identifier)
                .unwrap();

            // Compute Lagrange coefficient.
            let lambda_i =
                frost::derive_interpolating_value(&signature_share.identifier, signing_package)?;

            let binding_factor = binding_factor_list[signature_share.identifier].clone();

            // Compute the commitment share.
            let R_share = signing_package
                .signing_commitment(&signature_share.identifier)
                .to_group_commitment_share(&binding_factor);

            // Compute relation values to verify this signature share.
            signature_share.verify(&R_share, signer_pubkey, lambda_i, &challenge)?;
        }

        // We should never reach here; but we return the verification error to be safe.
        return Err(err);
    }

    Ok(signature)
}

/// Randomized params for a signing instance of randomized FROST.
pub struct RandomizedParams<C: Ciphersuite> {
    /// The randomizer, also called `alpha`
    randomizer: frost_core::Scalar<C>,
    /// The generator multiplied by the randomizer.
    randomizer_point: <C::Group as Group>::Element,
    /// The randomized group public key. The group public key added to the randomizer point.
    randomized_group_public_key: frost_core::VerifyingKey<C>,
}

impl<C> RandomizedParams<C>
where
    C: Ciphersuite,
{
    /// Create a new RandomizedParams for the given [`PublicKeyPackage`]
    pub fn new<R: RngCore + CryptoRng>(
        public_key_package: &PublicKeyPackage<C>,
        mut rng: R,
    ) -> Self {
        let randomizer = <<C::Group as Group>::Field as Field>::random(&mut rng);
        let randomizer_point = <C::Group as Group>::generator() * randomizer;

        let group_public_point = public_key_package.group_public.to_element();

        let randomized_group_public_point = group_public_point + randomizer_point;
        let randomized_group_public_key = VerifyingKey::new(randomized_group_public_point);

        Self {
            randomizer,
            randomizer_point,
            randomized_group_public_key,
        }
    }

    /// Return the randomizer.
    ///
    /// It can be useful to the coordinator, e.g. to generate the ZK proof
    /// in Zcash. It MUST NOT be sent to other parties.
    pub fn randomizer(&self) -> &frost_core::Scalar<C> {
        &self.randomizer
    }

    /// Return the randomizer point.
    ///
    /// It must be sent by the coordinator to each participant when signing.
    pub fn randomizer_point(&self) -> &<C::Group as Group>::Element {
        &self.randomizer_point
    }

    /// Return the randomized group public key.
    ///
    /// It can be used to verify the final signature.
    pub fn randomized_group_public_key(&self) -> &frost_core::VerifyingKey<C> {
        &self.randomized_group_public_key
    }
}
