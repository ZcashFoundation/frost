//! An implementation of FROST (Flexible Round-Optimized Schnorr Threshold)
//! signatures.
//!
//! If you are interested in deploying FROST, please do not hesitate to consult the FROST authors.
//!
//! This implementation currently only supports key generation using a central
//! dealer. In the future, we will add support for key generation via a DKG,
//! as specified in the FROST paper.
//!
//! Internally, generate_with_dealer generates keys using Verifiable Secret
//! Sharing, where shares are generated using Shamir Secret Sharing.

use std::{
    collections::{BTreeMap, HashMap},
    fmt::{self, Debug},
    ops::Index,
};

#[cfg(any(test, feature = "test-impl"))]
use hex::FromHex;

mod identifier;
pub mod keys;
pub mod round1;
pub mod round2;

use crate::{
    scalar_mul::VartimeMultiscalarMul, Ciphersuite, Element, Error, Field, Group, Scalar, Signature,
};

pub use self::identifier::Identifier;

/// The binding factor, also known as _rho_ (ρ)
///
/// Ensures each signature share is strongly bound to a signing set, specific set
/// of commitments, and a specific message.
///
/// <https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md>
#[derive(Clone, PartialEq, Eq)]
pub struct BindingFactor<C: Ciphersuite>(Scalar<C>);

impl<C> BindingFactor<C>
where
    C: Ciphersuite,
{
    /// Deserializes [`BindingFactor`] from bytes.
    pub fn from_bytes(
        bytes: <<C::Group as Group>::Field as Field>::Serialization,
    ) -> Result<Self, Error<C>> {
        <<C::Group as Group>::Field>::deserialize(&bytes)
            .map(|scalar| Self(scalar))
            .map_err(|e| e.into())
    }

    /// Serializes [`BindingFactor`] to bytes.
    pub fn to_bytes(&self) -> <<C::Group as Group>::Field as Field>::Serialization {
        <<C::Group as Group>::Field>::serialize(&self.0)
    }
}

impl<C> Debug for BindingFactor<C>
where
    C: Ciphersuite,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("BindingFactor")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

/// A list of binding factors and their associated identifiers.
#[derive(Clone)]
pub struct BindingFactorList<C: Ciphersuite>(BTreeMap<Identifier<C>, BindingFactor<C>>);

impl<C> BindingFactorList<C>
where
    C: Ciphersuite,
{
    /// Create a new [`BindingFactorList`] from a vector of binding factors.
    #[cfg(feature = "internals")]
    pub fn new(binding_factors: BTreeMap<Identifier<C>, BindingFactor<C>>) -> Self {
        Self(binding_factors)
    }

    /// Return iterator through all factors.
    pub fn iter(&self) -> impl Iterator<Item = (&Identifier<C>, &BindingFactor<C>)> {
        self.0.iter()
    }
}

impl<C> Index<Identifier<C>> for BindingFactorList<C>
where
    C: Ciphersuite,
{
    type Output = BindingFactor<C>;

    // Get the binding factor of a participant in the list.
    //
    // [`binding_factor_for_participant`] in the spec
    //
    // [`binding_factor_for_participant`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-4.3
    fn index(&self, identifier: Identifier<C>) -> &Self::Output {
        &self.0[&identifier]
    }
}

/// [`compute_binding_factors`] in the spec
///
/// [`compute_binding_factors`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-10.html#section-4.4
#[cfg_attr(feature = "internals", visibility::make(pub))]
pub(crate) fn compute_binding_factor_list<C>(
    signing_package: &SigningPackage<C>,
    additional_prefix: &[u8],
) -> BindingFactorList<C>
where
    C: Ciphersuite,
{
    let preimages = signing_package.binding_factor_preimages(additional_prefix);

    BindingFactorList(
        preimages
            .iter()
            .map(|(identifier, preimage)| {
                let binding_factor = C::H1(preimage);
                (*identifier, BindingFactor(binding_factor))
            })
            .collect(),
    )
}

#[cfg(any(test, feature = "test-impl"))]
impl<C> FromHex for BindingFactor<C>
where
    C: Ciphersuite,
{
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let v: Vec<u8> = FromHex::from_hex(hex).map_err(|_| "invalid hex")?;
        match v.try_into() {
            Ok(bytes) => Self::from_bytes(bytes).map_err(|_| "malformed scalar encoding"),
            Err(_) => Err("malformed scalar encoding"),
        }
    }
}

// TODO: pub struct Lagrange<C: Ciphersuite>(Scalar);

/// Generates the lagrange coefficient for the i'th participant.
#[cfg_attr(feature = "internals", visibility::make(pub))]
fn derive_interpolating_value<C: Ciphersuite>(
    signer_id: &Identifier<C>,
    signing_package: &SigningPackage<C>,
) -> Result<Scalar<C>, Error<C>> {
    let zero = <<C::Group as Group>::Field>::zero();

    let mut num = <<C::Group as Group>::Field>::one();
    let mut den = <<C::Group as Group>::Field>::one();

    // Ala the sorting of B, just always sort by identifier in ascending order
    //
    // https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#encoding-operations-dep-encoding
    for commitment in signing_package.signing_commitments() {
        if commitment.identifier == *signer_id {
            continue;
        }

        num *= commitment.identifier;

        den *= commitment.identifier - *signer_id;
    }

    if den == zero {
        return Err(Error::DuplicatedShares);
    }

    // TODO(dconnolly): return this error if the inversion result == zero
    let lagrange_coeff = num * <<C::Group as Group>::Field>::invert(&den).unwrap();

    Ok(lagrange_coeff)
}

/// Generated by the coordinator of the signing operation and distributed to
/// each signing party
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct SigningPackage<C: Ciphersuite> {
    /// The set of commitments participants published in the first round of the
    /// protocol.
    signing_commitments: HashMap<Identifier<C>, round1::SigningCommitments<C>>,
    /// Message which each participant will sign.
    ///
    /// Each signer should perform protocol-specific verification on the
    /// message.
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
            deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
        )
    )]
    message: Vec<u8>,
    /// Ciphersuite ID for serialization
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "crate::ciphersuite_serialize::<_, C>")
    )]
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "crate::ciphersuite_deserialize::<_, C>")
    )]
    ciphersuite: (),
}

impl<C> SigningPackage<C>
where
    C: Ciphersuite,
{
    /// Create a new `SigningPackage`
    ///
    /// The `signing_commitments` are sorted by participant `identifier`.
    pub fn new(
        signing_commitments: Vec<round1::SigningCommitments<C>>,
        message: &[u8],
    ) -> SigningPackage<C> {
        SigningPackage {
            signing_commitments: signing_commitments
                .into_iter()
                .map(|s| (s.identifier, s))
                .collect(),
            message: message.to_vec(),
            ciphersuite: (),
        }
    }

    /// Get a signing commitment by its participant identifier.
    pub fn signing_commitment(&self, identifier: &Identifier<C>) -> round1::SigningCommitments<C> {
        self.signing_commitments[identifier]
    }

    /// Get the signing commitments, sorted by the participant indices
    pub fn signing_commitments(&self) -> Vec<round1::SigningCommitments<C>> {
        let mut signing_commitments: Vec<round1::SigningCommitments<C>> =
            self.signing_commitments.values().cloned().collect();
        signing_commitments.sort_by_key(|a| a.identifier);
        signing_commitments
    }

    /// Get the message to be signed
    pub fn message(&self) -> &Vec<u8> {
        &self.message
    }

    /// Compute the preimages to H1 to compute the per-signer binding factors
    // We separate this out into its own method so it can be tested
    #[cfg_attr(feature = "internals", visibility::make(pub))]
    pub fn binding_factor_preimages(
        &self,
        additional_prefix: &[u8],
    ) -> Vec<(Identifier<C>, Vec<u8>)> {
        let mut binding_factor_input_prefix = vec![];

        // The message is hashed with H4 to force the variable-length message
        // into a fixed-length byte string, same for hashing the variable-sized
        // (between runs of the protocol) set of group commitments, but with H5.
        binding_factor_input_prefix.extend_from_slice(C::H4(self.message.as_slice()).as_ref());
        binding_factor_input_prefix.extend_from_slice(
            C::H5(&round1::encode_group_commitments(self.signing_commitments())[..]).as_ref(),
        );
        binding_factor_input_prefix.extend_from_slice(additional_prefix);

        self.signing_commitments()
            .iter()
            .map(|c| {
                let mut binding_factor_input = vec![];

                binding_factor_input.extend_from_slice(&binding_factor_input_prefix);
                binding_factor_input.extend_from_slice(c.identifier.serialize().as_ref());
                (c.identifier, binding_factor_input)
            })
            .collect()
    }
}

/// The product of all signers' individual commitments, published as part of the
/// final signature.
#[derive(Clone, PartialEq, Eq)]
pub struct GroupCommitment<C: Ciphersuite>(pub(super) Element<C>);

impl<C> GroupCommitment<C>
where
    C: Ciphersuite,
{
    /// Return the underlying element.
    #[cfg(feature = "internals")]
    pub fn to_element(self) -> <C::Group as Group>::Element {
        self.0
    }
}

// impl<C> Debug for GroupCommitment<C> where C: Ciphersuite {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         f.debug_tuple("GroupCommitment")
//             .field(&hex::encode(self.0.compress().to_bytes()))
//             .finish()
//     }
// }

/// Generates the group commitment which is published as part of the joint
/// Schnorr signature.
///
/// Implements [`compute_group_commitment`] from the spec.
///
/// [`compute_group_commitment`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-10.html#section-4.5
#[cfg_attr(feature = "internals", visibility::make(pub))]
fn compute_group_commitment<C>(
    signing_package: &SigningPackage<C>,
    binding_factor_list: &BindingFactorList<C>,
) -> Result<GroupCommitment<C>, Error<C>>
where
    C: Ciphersuite,
{
    let identity = <C::Group as Group>::identity();

    let mut group_commitment = <C::Group as Group>::identity();

    // Number of signing participants we are iterating over.
    let n = signing_package.signing_commitments().len();

    let mut binding_scalars = Vec::with_capacity(n);

    let mut binding_elements = Vec::with_capacity(n);

    // Ala the sorting of B, just always sort by identifier in ascending order
    //
    // https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#encoding-operations-dep-encoding
    for commitment in signing_package.signing_commitments() {
        // The following check prevents a party from accidentally revealing their share.
        // Note that the '&&' operator would be sufficient.
        if identity == commitment.binding.0 || identity == commitment.hiding.0 {
            return Err(Error::IdentityCommitment);
        }

        let binding_factor = binding_factor_list[commitment.identifier].clone();

        // Collect the binding commitments and their binding factors for one big
        // multiscalar multiplication at the end.
        binding_elements.push(commitment.binding.0);
        binding_scalars.push(binding_factor.0);

        group_commitment = group_commitment + commitment.hiding.0;
    }

    let accumulated_binding_commitment: Element<C> =
        VartimeMultiscalarMul::<C>::vartime_multiscalar_mul(binding_scalars, binding_elements);

    group_commitment = group_commitment + accumulated_binding_commitment;

    Ok(GroupCommitment(group_commitment))
}

////////////////////////////////////////////////////////////////////////////////
// Aggregation
////////////////////////////////////////////////////////////////////////////////

/// Aggregates the signature shares to produce a final signature that
/// can be verified with the group public key.
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
    signing_package: &SigningPackage<C>,
    signature_shares: &[round2::SignatureShare<C>],
    pubkeys: &keys::PublicKeyPackage<C>,
) -> Result<Signature<C>, Error<C>>
where
    C: Ciphersuite,
{
    // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
    // binding factor.
    let binding_factor_list: BindingFactorList<C> =
        compute_binding_factor_list(signing_package, &[]);

    // Compute the group commitment from signing commitments produced in round one.
    let group_commitment = compute_group_commitment(signing_package, &binding_factor_list)?;

    // The aggregation of the signature shares by summing them up, resulting in
    // a plain Schnorr signature.
    //
    // Implements [`aggregate`] from the spec.
    //
    // [`aggregate`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-5.3
    let mut z = <<C::Group as Group>::Field>::zero();

    for signature_share in signature_shares {
        z = z + signature_share.signature.z_share;
    }

    let signature = Signature {
        R: group_commitment.0,
        z,
    };

    // Verify the aggregate signature
    let verification_result = pubkeys
        .group_public
        .verify(signing_package.message(), &signature);

    // Only if the verification of the aggregate signature failed; verify each share to find the cheater.
    // This approach is more efficient since we don't need to verify all shares
    // if the aggregate signature is valid (which should be the common case).
    if let Err(err) = verification_result {
        // Compute the per-message challenge.
        let challenge = crate::challenge::<C>(
            &group_commitment.0,
            &pubkeys.group_public.element,
            signing_package.message().as_slice(),
        );

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
                derive_interpolating_value(&signature_share.identifier, signing_package)?;

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
