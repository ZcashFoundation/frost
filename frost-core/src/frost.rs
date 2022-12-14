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

use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
    fmt::{self, Debug},
    ops::Index,
};

use hex::FromHex;

mod identifier;
pub mod keys;
pub mod round1;
pub mod round2;

use crate::{Ciphersuite, Element, Error, Field, Group, Scalar, Signature};

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

impl<C> From<&SigningPackage<C>> for BindingFactorList<C>
where
    C: Ciphersuite,
{
    // [`compute_binding_factors`] in the spec
    //
    // [`compute_binding_factors`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-4.4
    fn from(signing_package: &SigningPackage<C>) -> BindingFactorList<C> {
        let preimages = signing_package.binding_factor_preimages();

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
fn derive_lagrange_coeff<C: Ciphersuite>(
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
pub struct SigningPackage<C: Ciphersuite> {
    /// The set of commitments participants published in the first round of the
    /// protocol.
    signing_commitments: HashMap<Identifier<C>, round1::SigningCommitments<C>>,
    /// Message which each participant will sign.
    ///
    /// Each signer should perform protocol-specific verification on the
    /// message.
    message: Vec<u8>,
}

impl<C> SigningPackage<C>
where
    C: Ciphersuite,
{
    /// Create a new `SigingPackage`
    ///
    /// The `signing_commitments` are sorted by participant `identifier`.
    pub fn new(
        signing_commitments: Vec<round1::SigningCommitments<C>>,
        message: Vec<u8>,
    ) -> SigningPackage<C> {
        SigningPackage {
            signing_commitments: signing_commitments
                .into_iter()
                .map(|s| (s.identifier, s))
                .collect(),
            message,
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

    /// Compute the preimages to H3 to compute the per-signer binding factors
    // We separate this out into its own method so it can be tested
    pub fn binding_factor_preimages(&self) -> Vec<(Identifier<C>, Vec<u8>)> {
        let mut binding_factor_input_prefix = vec![];

        binding_factor_input_prefix.extend_from_slice(C::H4(self.message.as_slice()).as_ref());
        binding_factor_input_prefix.extend_from_slice(
            C::H5(&round1::encode_group_commitments(self.signing_commitments())[..]).as_ref(),
        );

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
#[derive(PartialEq, Eq)]
pub struct GroupCommitment<C: Ciphersuite>(pub(super) Element<C>);

// impl<C> Debug for GroupCommitment<C> where C: Ciphersuite {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         f.debug_tuple("GroupCommitment")
//             .field(&hex::encode(self.0.compress().to_bytes()))
//             .finish()
//     }
// }

impl<C> TryFrom<&SigningPackage<C>> for GroupCommitment<C>
where
    C: Ciphersuite,
{
    type Error = Error<C>;

    /// Generates the group commitment which is published as part of the joint
    /// Schnorr signature.
    ///
    /// Implements [`compute_group_commitment`] from the spec.
    ///
    /// [`compute_group_commitment`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html#section-4.5
    fn try_from(signing_package: &SigningPackage<C>) -> Result<GroupCommitment<C>, Error<C>> {
        let binding_factor_list: BindingFactorList<C> = signing_package.into();

        let identity = <C::Group>::identity();

        let mut group_commitment = <C::Group>::identity();

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

            group_commitment = group_commitment
                + (commitment.hiding.0 + (commitment.binding.0 * binding_factor.0));
        }

        Ok(GroupCommitment(group_commitment))
    }
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
    let binding_factor_list: BindingFactorList<C> = signing_package.into();

    // Compute the group commitment from signing commitments produced in round one.
    let group_commitment = GroupCommitment::<C>::try_from(signing_package)?;

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
        let lambda_i = derive_lagrange_coeff(&signature_share.identifier, signing_package)?;

        let binding_factor = binding_factor_list[signature_share.identifier].clone();

        // Compute the commitment share.
        let R_share = signing_package
            .signing_commitment(&signature_share.identifier)
            .to_group_commitment_share(&binding_factor);

        // Compute relation values to verify this signature share.
        signature_share.verify(&R_share, signer_pubkey, lambda_i, &challenge)?;
    }

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

    Ok(Signature {
        R: group_commitment.0,
        z,
    })
}
