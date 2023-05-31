use crate::Ed25519Sha512;
use ed25519_dalek::Verifier;

#[cfg(test)]
pub fn verify_signature(
    msg: &[u8],
    group_signature: frost_core::Signature<Ed25519Sha512>,
    group_pubkey: frost_core::VerifyingKey<Ed25519Sha512>,
) {
    let sig = {
        let bytes: [u8; 64] = group_signature.to_bytes();
        ed25519_dalek::Signature::from(bytes)
    };
    let pub_key = {
        let bytes = group_pubkey.to_bytes();
        ed25519_dalek::PublicKey::from_bytes(&bytes).unwrap()
    };
    // Check that signature validation has the expected result.
    assert!(pub_key.verify(msg, &sig).is_ok());
}
