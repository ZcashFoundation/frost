# Understanding FROST

This explains the main concepts and flows of FROST in a generic manner. These
are important to understand how to use the library, but rest assured that the
[Tutorial](tutorial.md) will have more concrete information.

FROST is a threshold signature scheme. It allows splitting a Schnorr signing key
into `n` shares for a threshold `t`, such that `t` (or more) participants can
together generate a signature that can be validated by the corresponding verifying
key. One important aspect is that the resulting signature is indistinguishable from a
non-threshold signature from the point of view of signature verifiers.

```admonish note
FROST only supports Schnorr signatures. Therefore it can't produce
ECDSA signatures.
```

## Key Generation

There are two options for generating FROST key shares. In both cases, after the
key generation procedure, each participant will get:

- a **secret share**;
- a **verifying share** (which can be used by other participants to verify the
  signature shares the participant produces);
- a **group verifying key**, which is the public key matching the private key that was
  split into shares; it is used to verify the final signature generated with FROST.

### Trusted Dealer Generation

An existing key (which can be freshly generated) is split into shares. It's the
simplest approach, but it has the downside of requiring the entire key to exist
in memory at some point in time, which may not be desired in high security
applications. However, it is much simpler to set up. It requires an
[authenticated and confidential communication
channel](https://frost.zfnd.org/terminology.html#peer-to-peer-channel) to
distribute each share to their respective participants.

[Learn how to do Trusted Dealer Generation with the ZF FROST library](tutorial.md#generating-key-shares-with-a-trusted-dealer).

### Distributed Key Generation

A two-round protocol after which each participant will have their share of the
secret, without the secret being ever present in its entirety in any
participant's memory. Its downside is that it requires a [broadcast
channel](https://frost.zfnd.org/terminology.html#broadcast-channel) as well as
an [authenticated and confidential communication
channel](https://frost.zfnd.org/terminology.html#peer-to-peer-channel) between
each pair of participants, which may be difficult to deploy in practice.

[Learn how to do Distributed Key Generation with the ZF FROST
library](tutorial/dkg.md).

## Signing

Signing with FROST starts with a Coordinator (which can be one of the
share holders, or not) which selects the message to be signed and
the participants that will generate the signature.

Each participant sends fresh nonce commitments to the Coordinator, which then
consolidates them and sends them to each participant. Each one will then produce
a signature share, which is sent to the Coordinator who finally aggregates them
and produces the final signature.

```admonish note
If having a single coordinator is not desired, then all participants
can act as coordinators. Refer to the
[spec](https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#removing-the-coordinator-role-no-coordinator)
for more information.
```

```admonish warning
ALL participants who are selected for generating the signature need
to produce their share, even if there are more than `t` of them.
For example, in 2-of-3 signing, if 3 participants are selected,
them all 3 must produce signature shares in order for the Coordinator
be able to produce the final signature. Of course, the Coordinator
is still free to start the process with only 2 participants if they wish.
```

## Verifying

Signature verification is carried out as normal with single-party signatures,
along with the signed message and the group verifying key as inputs.

## Repairing

Repairing shares allow participants to help another participant recover their
share if they have lost it, or also issue a new share to a new participant
(while keeping the same threshold).

The repair share functionality requires a threshold of participants to work.
For example, in a 2-of-3 scenario, two participants can help the third recover
their share, or they could issue a new share to move to a 2-of-4 group.

The functionality works in such a way that each participant running the repair
share function is not able to obtain the share that is being recovered or
issued.

## Refreshing

Refreshing shares allow participants (or a subset of them) to update their
shares in a way that maintains the same group public key. Some applications are:

- Make it harder for attackers to compromise the shares. For example, in a
  2-of-3 threshold scenario, if an attacker steals one participant's device and
  all participants refresh their shares, the attacker will need to start over
  and steal two shares instead of just one more.
- Remove a participant from the group. For example, in a 2-of-3 threshold
  scenario, if two participants decide to remove the third they can both refresh
  their shares and the third participant would no longer be able to participate
  in signing sessions with the others. (They can also then use the repair share
  functionality to issue a new share and move from 2-of-2 back to 2-of-3.)

```admonish note
This is also possible via Distributed Key Generation but this has not yet been
implemented.
```

## Ciphersuites

FROST is a generic protocol that works with any adequate prime-order group,
which in practice are constructed from elliptic curves. The spec specifies
five ciphersuites with the Ristretto255, Ed25519, Ed448, P-256 and secp256k1
groups. It's possible (though not recommended) to use your own ciphersuite.
