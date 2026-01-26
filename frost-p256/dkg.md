# Distributed Key Generation (DKG)

The DKG module supports generating FROST key shares in a distributed manner,
without a trusted dealer.

For a higher level tutorial on how to use it, refer to the [ZF FROST
Book](https://frost.zfnd.org/tutorial/dkg.html).

## Example

This examples shows the whole procedure in a single program. Of course, in
practice, each participant will run their own part in their own devices and
packages will need to be sent between them, respecting the DKG requirements of
using [authenticated and confidential communication
channels](https://frost.zfnd.org/terminology.html#peer-to-peer-channel),
additionally with a [**broadcast
channel**](https://frost.zfnd.org/terminology.html#broadcast-channel) for the
first round of communication to ensure all participants have the same value.

```rust
# // ANCHOR: dkg_import
use std::collections::BTreeMap;

use frost_p256 as frost;

let mut rng = rand::rngs::OsRng;

let max_signers = 5;
let min_signers = 3;
# // ANCHOR_END: dkg_import

////////////////////////////////////////////////////////////////////////////
// Key generation, Round 1
////////////////////////////////////////////////////////////////////////////

// Keep track of each participant's round 1 secret package.
// In practice each participant will keep its copy; no one
// will have all the participant's packages.
let mut round1_secret_packages = BTreeMap::new();

// Keep track of all round 1 packages sent to the given participant.
// This is used to simulate the broadcast; in practice the packages
// will be sent through a [**broadcast
// channel**](https://frost.zfnd.org/terminology.html#broadcast-channel)
// on top of an [authenticated and confidential communication
// channel](https://frost.zfnd.org/terminology.html#peer-to-peer-channel).
let mut received_round1_packages = BTreeMap::new();

// For each participant, perform the first part of the DKG protocol.
// In practice, each participant will perform this on their own environments.
for participant_index in 1..=max_signers {
    let participant_identifier = participant_index.try_into().expect("should be nonzero");
    # // ANCHOR: dkg_part1
    let (round1_secret_package, round1_package) = frost::keys::dkg::part1(
        participant_identifier,
        max_signers,
        min_signers,
        &mut rng,
    )?;
    # // ANCHOR_END: dkg_part1

    // Store the participant's secret package for later use.
    // In practice each participant will store it in their own environment.
    round1_secret_packages.insert(participant_identifier, round1_secret_package);

    // "Send" the round 1 package to all other participants. In this
    // test this is simulated using a BTreeMap; in practice this will be
    // sent through a [**broadcast
    // channel**](https://frost.zfnd.org/terminology.html#broadcast-channel)
    // on top of an [authenticated and confidential communication
    // channel](https://frost.zfnd.org/terminology.html#peer-to-peer-channel).
    for receiver_participant_index in 1..=max_signers {
        if receiver_participant_index == participant_index {
            continue;
        }
        let receiver_participant_identifier: frost::Identifier = receiver_participant_index
            .try_into()
            .expect("should be nonzero");
        received_round1_packages
            .entry(receiver_participant_identifier)
            .or_insert_with(BTreeMap::new)
            .insert(participant_identifier, round1_package.clone());
    }
}

////////////////////////////////////////////////////////////////////////////
// Key generation, Round 2
////////////////////////////////////////////////////////////////////////////

// Keep track of each participant's round 2 secret package.
// In practice each participant will keep its copy; no one
// will have all the participant's packages.
let mut round2_secret_packages = BTreeMap::new();

// Keep track of all round 2 packages sent to the given participant.
// This is used to simulate the broadcast; in practice the packages
// will be sent through an [authenticated and confidential communication
// channel](https://frost.zfnd.org/terminology.html#peer-to-peer-channel).
let mut received_round2_packages = BTreeMap::new();

// For each participant, perform the second part of the DKG protocol.
// In practice, each participant will perform this on their own environments.
for participant_index in 1..=max_signers {
    let participant_identifier = participant_index.try_into().expect("should be nonzero");
    let round1_secret_package = round1_secret_packages
        .remove(&participant_identifier)
        .unwrap();
    let round1_packages = &received_round1_packages[&participant_identifier];
    # // ANCHOR: dkg_part2
    let (round2_secret_package, round2_packages) =
        frost::keys::dkg::part2(round1_secret_package, round1_packages)?;
    # // ANCHOR_END: dkg_part2

    // Store the participant's secret package for later use.
    // In practice each participant will store it in their own environment.
    round2_secret_packages.insert(participant_identifier, round2_secret_package);

    // "Send" the round 2 package to all other participants. In this
    // test this is simulated using a BTreeMap; in practice this will be
    // sent through an [authenticated and confidential communication
    // channel](https://frost.zfnd.org/terminology.html#peer-to-peer-channel).
    // Note that, in contrast to the previous part, here each other participant
    // gets its own specific package.
    for (receiver_identifier, round2_package) in round2_packages {
        received_round2_packages
            .entry(receiver_identifier)
            .or_insert_with(BTreeMap::new)
            .insert(participant_identifier, round2_package);
    }
}

////////////////////////////////////////////////////////////////////////////
// Key generation, final computation
////////////////////////////////////////////////////////////////////////////

// Keep track of each participant's long-lived key package.
// In practice each participant will keep its copy; no one
// will have all the participant's packages.
let mut key_packages = BTreeMap::new();

// Keep track of each participant's public key package.
// In practice, if there is a Coordinator, only they need to store the set.
// If there is not, then all candidates must store their own sets.
// All participants will have the same exact public key package.
let mut pubkey_packages = BTreeMap::new();

// For each participant, perform the third part of the DKG protocol.
// In practice, each participant will perform this on their own environments.
for participant_index in 1..=max_signers {
    let participant_identifier = participant_index.try_into().expect("should be nonzero");
    let round2_secret_package = &round2_secret_packages[&participant_identifier];
    let round1_packages = &received_round1_packages[&participant_identifier];
    let round2_packages = &received_round2_packages[&participant_identifier];
    # // ANCHOR: dkg_part3
    let (key_package, pubkey_package) = frost::keys::dkg::part3(
        round2_secret_package,
        round1_packages,
        round2_packages,
    )?;
    # // ANCHOR_END: dkg_part3
    key_packages.insert(participant_identifier, key_package);
    pubkey_packages.insert(participant_identifier, pubkey_package);
}

// With its own key package and the pubkey package, each participant can now proceed
// to sign with FROST.
# Ok::<(), frost::Error>(())
```
