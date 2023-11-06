//! Test for Verifiable Secret Redistribution (AKA resharing).

use std::collections::BTreeMap;

use rand_core::{CryptoRng, RngCore};

use crate as frost;
use crate::{
    keys::{
        resharing::{reshare_step_1, reshare_step_2, SecretSubshare},
        PublicKeyPackage, SecretShare,
    },
    Ciphersuite, Identifier,
};

/// Check correctness of the verifiable secret redistribution protocol.
pub fn check_vsr<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    // Generate old keys and shares.
    let max_signers = 5;
    let old_min_signers = 3;
    let (old_shares, old_pubkeys): (BTreeMap<Identifier<C>, SecretShare<C>>, PublicKeyPackage<C>) =
        frost::keys::generate_with_dealer(
            max_signers,
            old_min_signers,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )
        .unwrap();

    // Signer 1, 2, and 4 will participate in resharing.
    let helper_1 = &old_shares[&Identifier::try_from(1).unwrap()];
    let helper_2 = &old_shares[&Identifier::try_from(2).unwrap()];
    let helper_4 = &old_shares[&Identifier::try_from(4).unwrap()];

    // They will reshare the key amongst themselves, plus new signer 5.
    // Signer 3 will be excluded.
    let new_signer_5_ident = Identifier::try_from(5).unwrap();
    let new_signer_idents = [
        helper_1.identifier,
        helper_2.identifier,
        helper_4.identifier,
        new_signer_5_ident,
    ];

    // The threshold will be changed from 3 to 2.
    let new_min_signers = 2;

    // Each helper generates their random coefficients and commitments.
    let helper_1_subshares = reshare_step_1(
        &helper_1.signing_share,
        &mut rng,
        new_min_signers,
        &new_signer_idents,
    )
    .expect("error computing resharing step 1 for helper 1");

    let helper_2_subshares = reshare_step_1(
        &helper_2.signing_share,
        &mut rng,
        new_min_signers,
        &new_signer_idents,
    )
    .expect("error computing resharing step 1 for helper 2");

    let helper_4_subshares = reshare_step_1(
        &helper_4.signing_share,
        &mut rng,
        new_min_signers,
        &new_signer_idents,
    )
    .expect("error computing resharing step 1 for helper 4");

    let all_subshares = BTreeMap::from([
        (helper_1.identifier, helper_1_subshares),
        (helper_2.identifier, helper_2_subshares),
        (helper_4.identifier, helper_4_subshares),
    ]);

    // Sort the subshares into a map of `recipient => sender => subshare`.
    let received_subshares = new_signer_idents
        .into_iter()
        .map(|recipient_id| {
            let received_subshares = all_subshares
                .iter()
                .map(|(&sender_id, sender_shares)| {
                    (sender_id, sender_shares[&recipient_id].clone())
                })
                .collect::<BTreeMap<_, _>>();
            (recipient_id, received_subshares)
        })
        .collect::<BTreeMap<Identifier<C>, BTreeMap<Identifier<C>, SecretSubshare<C>>>>();

    // Recipients of the resharing can now validate and compute their new shares.

    let (new_seckeys_1, new_pubkeys_1) = reshare_step_2(
        helper_1.identifier,
        &old_pubkeys,
        new_min_signers,
        &new_signer_idents,
        &received_subshares[&helper_1.identifier],
    )
    .expect("error computing reshared share for signer 1");

    let (new_seckeys_2, new_pubkeys_2) = reshare_step_2(
        helper_2.identifier,
        &old_pubkeys,
        new_min_signers,
        &new_signer_idents,
        &received_subshares[&helper_2.identifier],
    )
    .expect("error computing reshared share for signer 2");

    let (new_seckeys_4, new_pubkeys_4) = reshare_step_2(
        helper_4.identifier,
        &old_pubkeys,
        new_min_signers,
        &new_signer_idents,
        &received_subshares[&helper_4.identifier],
    )
    .expect("error computing reshared share for signer 4");

    let (new_seckeys_5, new_pubkeys_5) = reshare_step_2(
        new_signer_5_ident,
        &old_pubkeys,
        new_min_signers,
        &new_signer_idents,
        &received_subshares[&new_signer_5_ident],
    )
    .expect("error computing reshared share for signer 5");

    // all signers should compute the same group pubkeys.
    assert_eq!(new_pubkeys_1, new_pubkeys_2);
    assert_eq!(new_pubkeys_1, new_pubkeys_4);
    assert_eq!(new_pubkeys_1, new_pubkeys_5);
    assert_eq!(new_seckeys_1.verifying_key, new_seckeys_2.verifying_key);
    assert_eq!(new_seckeys_1.verifying_key, new_seckeys_4.verifying_key);
    assert_eq!(new_seckeys_1.verifying_key, new_seckeys_5.verifying_key);

    // The new pubkey package should be the same group key as the old one,
    // but with new coefficients and shares.
    assert_eq!(new_pubkeys_1.verifying_key, old_pubkeys.verifying_key);
    assert_ne!(new_pubkeys_1.verifying_shares, old_pubkeys.verifying_shares);

    assert_eq!(new_seckeys_1.min_signers, new_min_signers);
}
