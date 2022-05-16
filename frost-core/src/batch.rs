//! Performs batch Schnorr signature verification.
//!
//! Batch verification asks whether *all* signatures in some set are valid,
//! rather than asking whether *each* of them is valid. This allows sharing
//! computations among all signature verifications, performing less work overall
//! at the cost of higher latency (the entire batch must complete), complexity
//! of caller code (which must assemble a batch of signatures across
//! work-items), and loss of the ability to easily pinpoint failing signatures.

use std::convert::TryFrom;

use rand_core::{CryptoRng, RngCore};

use crate::{
    frost::{self, *},
    *,
};

/// A batch verification item.
///
/// This struct exists to allow batch processing to be decoupled from the
/// lifetime of the message. This is useful when using the batch verification
/// API in an async context.
#[derive(Clone, Debug)]
pub struct Item<C: Ciphersuite> {
    vk: VerifyingKey<C>,
    sig: Signature<C>,
    c: Challenge<C>,
}

impl<'msg, C, M> From<(VerifyingKey<C>, Signature<C>, &'msg M)> for Item<C>
where
    C: Ciphersuite,
    M: AsRef<[u8]>,
{
    fn from((vk, sig, msg): (VerifyingKey<C>, Signature<C>, &'msg M)) -> Self {
        // Compute c now to avoid dependency on the msg lifetime.

        let c = crate::challenge(&sig.R, &vk.element, msg.as_ref());

        Self { vk, sig, c }
    }
}

impl<C> Item<C>
where
    C: Ciphersuite,
{
    /// Perform non-batched verification of this `Item`.
    ///
    /// This is useful (in combination with `Item::clone`) for implementing
    /// fallback logic when batch verification fails. In contrast to
    /// [`VerifyingKey::verify`](crate::VerifyingKey::verify), which
    /// requires borrowing the message data, the `Item` type is unlinked
    /// from the lifetime of the message.
    pub fn verify_single(self) -> Result<(), Error> {
        VerifyingKey::try_from(self.vk_bytes).and_then(|vk| vk.verify_prehashed(&self.sig, self.c))
    }
}

#[derive(Default)]
/// A batch verification context.
pub struct Verifier<C: Ciphersuite> {
    /// Signature data queued for verification.
    signatures: Vec<Item<C>>,
}

impl<C> Verifier<C>
where
    C: Ciphersuite,
{
    /// Constructs a new batch verifier.
    pub fn new() -> Verifier<C> {
        Verifier::default()
    }

    /// Queues an Item for verification.
    pub fn queue<I: Into<Item<C>>>(&mut self, item: I) {
        self.signatures.push(item.into());
    }

    /// Performs batch verification, returning `Ok(())` if all signatures were
    /// valid and `Err` otherwise.
    ///
    /// The batch verification equation is:
    ///
    /// h_G * -[sum(z_i * s_i)]P_G + sum(\[z_i\]R_i + [z_i * c_i]VK_i) = 0_G
    ///
    /// which we split out into:
    ///
    /// h_G * -[sum(z_i * s_i)]P_G + sum(\[z_i\]R_i) + sum([z_i * c_i]VK_i) =
    /// 0_G
    ///
    /// so that we can use multiscalar multiplication speedups.
    ///
    /// where for each signature i,
    /// - VK_i is the verification key;
    /// - R_i is the signature's R value;
    /// - s_i is the signature's s value;
    /// - c_i is the hash of the message and other data;
    /// - z_i is a random 128-bit Scalar;
    /// - h_G is the cofactor of the group;
    /// - P_G is the generator of the subgroup;
    ///
    /// As follows elliptic curve scalar multiplication convention,
    /// scalar variables are lowercase and group point variables
    /// are uppercase. This does not exactly match the RedDSA
    /// notation in the [protocol specification §B.1][ps].
    ///
    /// [ps]: https://zips.z.cash/protocol/protocol.pdf#reddsabatchverify
    pub fn verify<R: RngCore + CryptoRng>(self, mut rng: R) -> Result<(), Error> {
        let n = self.signatures.len();

        let mut VK_coeffs = Vec::with_capacity(n);
        let mut VKs = Vec::with_capacity(n);
        let mut R_coeffs = Vec::with_capacity(self.signatures.len());
        let mut Rs = Vec::with_capacity(self.signatures.len());
        let mut P_coeff_acc = Scalar::zero();

        for item in self.signatures.iter() {
            let (z_bytes, R_bytes, c) = (item.sig.z_bytes, item.sig.R_bytes, item.c);

            let s = Scalar::from_bytes_mod_order(z_bytes);

            let R = {
                match CompressedRistretto::from_slice(&R_bytes).decompress() {
                    Some(point) => point,
                    None => return Err(Error::InvalidSignature),
                }
            };

            let VK = VerifyingKey::try_from(item.vk_bytes.bytes)?.point;

            let z = Scalar::random(&mut rng);

            let P_coeff = z * s;
            P_coeff_acc -= P_coeff;

            R_coeffs.push(z);
            Rs.push(R);

            VK_coeffs.push(Scalar::zero() + (z * c));
            VKs.push(VK);
        }

        use std::iter::once;

        let scalars = once(&P_coeff_acc)
            .chain(VK_coeffs.iter())
            .chain(R_coeffs.iter());

        let basepoints = [curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT];
        let points = basepoints.iter().chain(VKs.iter()).chain(Rs.iter());

        let check = RistrettoPoint::vartime_multiscalar_mul(scalars, points);

        if check == RistrettoPoint::identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
