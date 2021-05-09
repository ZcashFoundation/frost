# FROST messages

Proposes a message layout to exchange information between participants of a FROST setup using the [jubjub](https://github.com/zkcrypto/jubjub) curve.

## Motivation

Currently FROST library is complete for 2 round signatures with a dealer/aggregator setup.
This proposal is only considering that specific features, additions and upgrades will need to be made when DKG is implemented.

Assuming all participants have a FROST library available we need to define message structures in a way that data can be exchanged between participants. The proposal is a collection of data types so each side can do all the actions needed for a real life situation.

## Definitions

- `dealer`
- `aggregator`
- `signer`
- `nonce`
- `commitment`
- 

## Guide-level explanation

We propose a message separated in 2 parts, a header and a payload:

```rust
struct Message {
    header: Header,
    payload: Payload,
}
```

`Header` will look as follows:

```rust
struct Header {
    msg_type: MsgType,
    version: MsgVersion,
    sender: Participant,
    receiver: Participant, 
}
```

While `Payload` will be defined as:

```rust
enum Payload {
    DealerBroadcast(MsgDealerBroadcast),
    Commitments(MsgCommitments),
    SigningPackage(MsgSigningPackage),
    SignatureShare(MsgSignatureShare),
    FinalSignature(MsgFinalSignature),
}
```

All the messages and new types will be defined in a new file `src/frost/messages.rs`

## Reference-level explanation

Here we explore in detail the header types and all the message payloads. 

### Header

Fields of the header define new types. Proposed implementation for them is as follows:

```rust
#[repr(u8)]
#[non_exhaustive]
enum MsgType {
    DealerBroadcast,
    Commitments,
    SigningPackage,
    SignatureShare,
    FinalSignature,
}

struct MsgVersion(u8);

struct Participant(u8);
```

### Payloads

Each payload defines a new message:

```rust
// Dealer must send this message with initial data to each participant involved.
// With this, the participant should be able to build a `SharePackage` and use
//  the `sign()` function.
// `public_key` can be calculated from the `secret_key`.
// from `secret_key`.
struct MsgDealerBroadcast {
    // The secret key as a frost::Scalar.
    secret_key: frost::Scalar,
    // Commitment for the signer as a single jubjub::AffinePoint.
    commitment: jubjub::AffinePoint,
    // The public signing key that represents the entire group.
    group_public: GroupPublic,
}

// The point and verification bytes needed to generate the group public key
struct GroupPublic {
    // The point
    point: jubjub::AffinePoint,
    // The verification bytes
    bytes: [u8; 32],
}

// Each signer participant send to the aggregator the 2 points
//  needed for commitment building.
struct MsgCommitments {
    commitment: Commitment,
}

// A commitment specified by two AffinePoints.
struct Commitment {
    // The hiding Point.
    hiding: jubjub::AffinePoint,
    // The binding Point.
    binding: jubjub::AffinePoint,
}

// The aggergator decide what message is going to be signed and
// send it to each participant with all the commitments collected.
struct MsgSigningPackage {
    // The number of participants.
    participants: u8,
    // The collected commitments for each signer
    commitments: Vec<CollectedCommitments>,
    // The lenght of the message
    message_length: u64,
    // The message to be signed as bytes
    message: &'static [u8],
}

// The aggergator collected commitments for each signer in the
//  scheme.
struct CollectedCommitment {
    // Signer commitment
    signer_id: u8,
    // Commitment for this signer
    commitment: Commitment,
}

// Each signer send the signatures to the agregator who is going to collect them 
// and generate a final spend signature.
struct MsgSignatureShare {
    // The signature to be shared as a Scalar
    signature: frost::Scalar,
}

// The final signature is broadcasted by the aggegator 
// to any participant.
struct MsgFinalSignature {
    // Bytes needed to build the frost::Signature
    final_signature: FinalSignature,
}

// Final RedJubJub signature the aggergator has created.
struct FinalSignature {
    //
    r_bytes: [u8; 32],
    //
    s_bytes: [u8; 32],
}
```

## Validation

Validation is implemented to each new data type as needed. This will ensure the creation of valid messages before they are send and right after they are received. We create a trait for this as follows:

```rust
pub trait Validate {
    fn validate(&self) -> Result<&Self, MsgErr>;
}
```

And we implement where needed. For example, in the header, sender and receiver can't be the same:

```rust
impl Validate for Header {
    fn validate(&self) -> Result<&Self, MsgErr> {
        if self.sender.0 == self.receiver.0 {
            return Err(MsgErr::SameSenderAndReceiver);
        }
        Ok(self)
    }
}
```

This will require to have validation error messages as:

```rust
use thiserror::Error;

#[derive(Clone, Error, Debug)]
pub enum MsgErr {
    #[error("sender and receiver are the same")]
    SameSenderAndReceiver,
}
```

Then to create a valid `Header` in the sender side we call:

```rust
let header = Validate::validate(&Header {
    ..
}).expect("a valid header");
```

The receiver side will validate the header using the same method. Instead of panicking the error can be ignored to don't crash and keep waiting for other (potentially valid) messages.

```rust
if let Ok(header) = msg.header.validate() {
    ..
}
```

## Serialization/Deserialization

Each message struct needs to serialize to bytes representation before it is sent through the wire and must deserialize to the same struct (round trip) on the receiver side. We use `serde` and macro derivations (`Serialize` and `Deserialize`) to automatically implement where possible.

This will require deriving serde in several types defined in `frost.rs`. 
Manual implementation of serialization/deserialization will be located at a new mod `src/frost/serialize.rs`.

### Byte order

Each byte chunk specified below is in little-endian order unless is specified otherwise.

### Header

The `Header` part of the message is 4 bytes total:

Bytes | Field name | Data type
------|------------|-----------
1     | msg_type   | u8
1     | version    | u8
1     | sender     | u8
1     | receiver   | u8

### Primitive types

`Payload`s use data types that we need to specify first. We have 2 primitive types inside the payload messages:

#### `Scalar`

`Scalar` is a an alias for `jubjub::Fr` and this is a `[u64; 4]` as documented in https://github.com/zkcrypto/jubjub/blob/main/src/fr.rs#L16

#### `AffinePoint`

Much of the math in FROST is done using `jubjub::ExtendedPoint`. This is a structure with 5 `jubjub::Fq`s as defined in https://github.com/zkcrypto/jubjub/blob/main/src/lib.rs#L128-L134

Each `Fq` needed to form a `jubjub::ExtendedPoint` are `Scalar`s of `bls12_381` crate. Scalar here is `[u64; 4]` as documented in https://github.com/zkcrypto/bls12_381/blob/main/src/scalar.rs#L16

For message exchange `jubjub::AffinePoint`s are a better choice as they are shorter in bytes, they are formed of 2 `jubjub::Fq` instead of 5: https://github.com/zkcrypto/jubjub/blob/main/src/lib.rs#L70-L73

Conversion from one type to the other is trivial:

https://docs.rs/jubjub/0.6.0/jubjub/struct.AffinePoint.html#impl-From%3CExtendedPoint%3E
https://docs.rs/jubjub/0.6.0/jubjub/struct.ExtendedPoint.html#impl-From%3CAffinePoint%3E

### Payload

Payload part of the message is variable in size and depends on message type.

#### `MsgDealerBroadcast`

Bytes  | Field name  | Data type
-------|-------------|-----------
256    | secret_key  | Scalar
512    | commitments | AffinePoint
512+32 | group_public| GroupPublic

#### `MsgCommitments`

Bytes   | Field name | Data type
--------|------------|-----------
512+512 | commitment | Commitment

#### `MsgSigningPackage`

Bytes                  | Field name     | Data type
-----------------------|----------------|-----------
1                      | participants   | u8
(1+1024)*partipants    | commitments    | Vec<CollectedCommitments>
8                      | message_length | u64
message_length         | message        | [u8]

#### `SignatureShare`

Bytes | Field name | Data type
------|------------|-----------
256   | signature  | Scalar

#### `MsgFinalSignature`

Bytes | Field name       | Data type
------|------------------|-----------
64    | final_signature  | FinalSignature

## Not included

The following are a few things this RFC is not considering:

- After the dealer sends the initial `MsgDealerBroadcast` to all the participants, the aggregator must wait for signers to send the second message `MsgCommitments`. There is no timeout for this but only after the aggregator received all the commitments the process can continue. These restrictions and event waiting are not detailed in this RFC.
- This implementation considers not only communications between computer devices in the internet but allows the process to be done by other channels, the lack of timers can result in participants waiting forever for a message. It is the participants business to deal with this and other similars.
- The RFC does not describe a Service but just message structure and serialization.

## Testing plan

- Create a happy path unit test similar to https://github.com/ZcashFoundation/redjubjub/blob/frost-messages/tests/frost.rs#L7 and:
  - Make messages on each step.
  - Simulate send/receive.
  - Test round trip serialization/deserialization on each message.
- Create property tests for each message.
