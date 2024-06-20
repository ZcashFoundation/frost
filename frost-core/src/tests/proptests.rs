//! Ciphersuite-generic functions for proptests

use crate::*;
use proptest::prelude::*;
use rand_core::{CryptoRng, RngCore};

/// A signature test-case, containing signature data and expected validity.
#[derive(Clone, Debug)]
pub struct SignatureCase<C: Ciphersuite> {
    msg: Vec<u8>,
    sig: Signature<C>,
    vk: VerifyingKey<C>,
    invalid_vk: VerifyingKey<C>,
    is_valid: bool,
}

/// A modification to a test-case.
#[derive(Copy, Clone, Debug)]
pub enum Tweak {
    /// No-op, used to check that unchanged cases verify.
    None,
    /// Change the message the signature is defined for, invalidating the signature.
    ChangeMessage,
    /// Change the public key the signature is defined for, invalidating the signature.
    ChangePubkey,
    /* XXX implement this -- needs to regenerate a custom signature because the
       nonce commitment is fed into the hash, so it has to have torsion at signing
       time.
    /// Change the case to have a torsion component in the signature's `r` value.
    AddTorsion,
    */
    /* XXX implement this -- needs custom handling of field arithmetic.
    /// Change the signature's `s` scalar to be unreduced (mod L), invalidating the signature.
    UnreducedScalar,
    */
}

impl<C> SignatureCase<C>
where
    C: Ciphersuite,
{
    /// Create a new SignatureCase.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R, msg: Vec<u8>) -> Self {
        let sk = SigningKey::<C>::new(&mut rng);
        let sig = sk.sign(&mut rng, &msg);
        let vk = VerifyingKey::<C>::from(&sk);
        let invalid_vk = VerifyingKey::<C>::from(&SigningKey::new(&mut rng));
        Self {
            msg,
            sig,
            vk,
            invalid_vk,
            is_valid: true,
        }
    }

    /// Check that signature verification succeeds or fails, as expected.
    pub fn check(&self) -> bool {
        // The signature data is stored in (refined) byte types, but do a round trip
        // conversion to raw bytes to exercise those code paths.
        let _sig = {
            let bytes = self.sig.serialize().unwrap();
            Signature::<C>::deserialize(&bytes)
        };

        // Check that the verification key is a valid key.
        let _pub_key = VerifyingKey::<C>::deserialize(&self.vk.serialize().unwrap())
            .expect("The test verification key to be well-formed.");

        // Check that signature validation has the expected result.
        self.is_valid == self.vk.verify(&self.msg, &self.sig).is_ok()
    }

    /// Apply the given tweak to the signature test case.
    pub fn apply_tweak(&mut self, tweak: &Tweak) {
        match tweak {
            Tweak::None => {}
            Tweak::ChangeMessage => {
                // Changing the message makes the signature invalid.
                self.msg.push(90);
                self.is_valid = false;
            }
            Tweak::ChangePubkey => {
                // Changing the public key makes the signature invalid.
                self.vk = self.invalid_vk;
                self.is_valid = false;
            }
        }
    }
}

/// Tweak the proptest strategy
pub fn tweak_strategy() -> impl Strategy<Value = Tweak> {
    prop_oneof![
        10 => Just(Tweak::None),
        1 => Just(Tweak::ChangeMessage),
        1 => Just(Tweak::ChangePubkey),
    ]
}
