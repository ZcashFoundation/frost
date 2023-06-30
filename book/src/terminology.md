# Terminology

### _Broadcast channel_

A secure broadcast channel in the context of multi-party computation protocols
such as FROST has the following properties:

1. Consistent. Each participant has the same view of the message sent over the channel.
2. Authenticated. Players know that the message was in fact sent by the claimed sender. In practice, this
requirement is often fulfilled by a PKI.
3. Reliable Delivery. Player i knows that the message it sent was in fact received by the intended participants.
4. Unordered. The channel does not guarantee ordering of messages.

Possible deployment options:
- Echo-broadcast (Goldwasser-Lindell)
- Posting commitments to an authenticated centralized server that is trusted to
  provide a single view to all participants (also known as 'public bulletin board')

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

Peer-to-peer channels are authenticated, reliable, and unordered, per the
definitions above. Additionally, peer-to-peer channels are _confidential_; i.e.,
only participants `i` and `j` are allowed to know the contents of
a message `msg_i,j`.

Possible deployment options:
- Mutually authenticated TLS
- Wireguard

### _Threshold secret sharing_

Threshold secret sharing does not require a broadcast channel because the dealer is fully trusted.

### _Verifiable secret sharing_

Verifiable secret sharing requires a broadcast channel because the dealer is
_not_ fully trusted: keygen participants verify the VSS commitment which is
transmitted over the broadcast channel before accepting the shares distributed
from the dealer, to ensure all participants have the same view of the commitment.


