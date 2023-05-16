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
  provide a single view to all participants


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
from the dealer.


