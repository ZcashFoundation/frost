# Terminology

### _Broadcast channel_

A secure broadcast channel in the context of multi-party computation protocols
such as FROST must have a set of theoretical properties which can be a bit subtle
and depend on the specific protocol being implemented. However, most real
deployments use the protocol from the [Secure Computation Without
Agreement](https://eprint.iacr.org/2002/040) paper, which we describe below, and
which is also referred to as "echo broadcast". It has the following properties:
agreement (if an honest party outputs x, then all honest parties output x or
abort), validity (if the broadcaster is honest, then all honest parties output
the broadcast value) and non-triviality (if all parties are honest, they all
output the broadcast value).

The echo broadcast works as follows, for a party `P[1]` which wants to broadcast
a value `x` to the other `P[i]` parties for `1 < i <= n` where `n` is the number
of participants:

1. `P[1]` sends `x` to all other `n-1` parties.
2. For each `P[i]` other than `P[1]`:
   1. Set `x1` to the value received from `P[1]` in step 1, or to `null` if no
      value was received.
   2. Send `x1` to the other `n-2` parties (excluding `1` and `i` themselves).
   3. Set `r[j]` to the value that `i` will receive from the other `n-2` parties,
      indexed by their index `j`.
   4. Output `x1` if it is equal to every value in `r[j]` for all `j` in the
      other `n-2` parties. Otherwise, output `null`.

In the specific context of FROST, you will need to use the echo broadcast for
each participant to send their round 1 package to the other participants. This
means that you will need to run `n` instances of the echo-broadcast protocol
in parallel!

As an alternative to using echo-broadcast, other mechanisms are possible
depending on the application. For example, posting commitments (round 1
packages) to an authenticated centralized server that is trusted to provide a
single view to all participants (also known as 'public bulletin board')

### _Identifier_

An identifier is a non-zero scalar (i.e. a number in a range specific to the
ciphersuite) which identifies a specific party. There are no restrictions to
them other than being unique for each participant and being in the valid range.

In the ZF FROST library, they are either automatically generated incrementally
during key generation or converted from a `u16` using a
[`TryFrom<u16>`](https://docs.rs/frost-core/latest/frost_core/frost/struct.Identifier.html#impl-TryFrom%3Cu16%3E-for-Identifier%3CC%3E).

ZF FROST also allows deriving identifiers from arbitrary byte strings with
[`Identifier::derive()`](https://docs.rs/frost-core/latest/frost_core/frost/struct.Identifier.html#method.derive).
This allows deriving identifiers from usernames or emails, for example.

### _Peer to peer channel_

Peer-to-peer channels might need to be authenticated (DKG messages, and FROST
signing messages if cheater detection is required), meaning there is assurance
on who is the sender of a message, and might be confidential (DKG messages, and
FROST signing messages if the messages being signed are confidential), meaning
no other party listening to the communication can have access to the message.

In practice there are multiple possible deployment options:
- Mutually authenticated TLS
- Noise protocol
- Wireguard

### _Threshold secret sharing_

Threshold secret sharing does not require a broadcast channel because the dealer is fully trusted.

### _Verifiable secret sharing_

Verifiable secret sharing requires a broadcast channel because the dealer is
_not_ fully trusted: keygen participants verify the VSS commitment which is
transmitted over the broadcast channel before accepting the shares distributed
from the dealer, to ensure all participants have the same view of the commitment.
