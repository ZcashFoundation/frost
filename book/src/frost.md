# Understanding FROST

This explain the main concepts and flows of FROST in a generic manner. These
are important to understand how to use the library, but rest assured that the
[Tutorial](tutorial.md) will have more concrete information.

FROST is a threshold signature scheme. It allows splitting a Schnorr private key
into `n` shares for a threshold `t`, such that `t` (or more) participants can
together generate a signature that can be validated by the matching public key.
One important aspect is that the resulting signature is indistinguishable from a
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
  signature shares they produce);
- a **group public key**, which is the public key matching the private key that was
  split into shares.

### Trusted Dealer Generation

An existing key (which can be freshly generated) is split into shares. It's the
simplest approach, but it has the downside of requiring the entire key to exist
in memory at some point in time, which may not be desired in high security
applications. However, it is much simpler to set up. It requires an
authenticated and confidential communication channel to distribute each share to
their respective participants.

To learn how to do Trusted Dealer Generation with the ZF FROST library, see
TODO.

### Distribtuted Key Generation

A two-round protocol after which each participant will have their share of
the secret, without the secret being ever present in its entirety in any of the
participant's memory. Its downside is that it require a [broadcast
channel](https://frost.zfnd.org/terminology.html#broadcast-channel) on top of
authenticated and confidential communication channel between each pair of
participants, which may be difficult to deploy in practice. See guidelines in
TODO.

To learn how to do Distributed Key Generation with the ZF FROST
library, see TODO.



## Signing

Signing with FROST starts with a Coordinator (which can be one of the
share holders, or not) which selects the message to be signed and
the participants that will generated the signature.

Each participant sends a fresh signing commitment to the Coordinator, which then
consolidates them and sends them to each participant. Each one will then produce
a signature share, which is sent to the Coordinator who finally aggregates them
and produces the final signature.

```admonish note
If having a single coordinator is not desired, then all participants
can act as coordinators. Refer to the [spec](https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md#removing-the-coordinator-role-no-coordinator) for more information.
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

Signature verification is carried out as normal, along with the signed message
and the group public key as inputs.


## Ciphersuites

FROST is a generic protocol that works with any adequated prime-order group,
which in practice are elliptic curves. The spec specifies five "official"
ciphersuites with the Ristretto255, Ed25519, Ed448, P-256 and secp256k1
curves. But it's possible (though not recommended) to use your own
ciphersuite.
