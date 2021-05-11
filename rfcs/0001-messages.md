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
    sender: ParticipantID,
    receiver: ParticipantID,
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

struct ParticipantID(u8);
```

### Payloads

Each payload defines a new message:

```rust
/// Dealer must send this message with initial data to each participant involved.
/// With this, the participant should be able to build a `SharePackage` and use
/// the `sign()` function.
///
/// Note: `frost::SharePackage.public` can be calculated from `secret_share`.
struct MsgDealerBroadcast {
    /// This participant's secret key share: `frost::Share.value`.
    secret_share: frost::Scalar,
    /// Commitment for the signer as a single jubjub::AffinePoint.
    /// A set of commitments to the coefficients (which themselves are scalars)
    ///  for a secret polynomial _f_: `frost::SharePackage.share.commitment`
    share_commitment: Vec<jubjub::AffinePoint>,
    /// The public signing key that represents the entire group:
    ///  `frost::SharePackage.group_public`.
    group_public: jubjub::AffinePoint,
}

/// Each signer participant send to the aggregator the 2 points
///  needed for commitment building.
struct MsgCommitments {
    /// A commitment to a single signature by this signer:
    ///  `frost::SigningPackage.signing_commitments`
    signing_commitments: SigningCommitments,
}

/// A signing commitment from the first round of the signing protocol.
struct SigningCommitments {
    /// The hiding point: `frost::SigningCommitments.hiding`
    hiding: jubjub::AffinePoint,
    /// The binding point: `frost::SigningCommitments.binding`
    binding: jubjub::AffinePoint,
}

/// The aggregator decides what message is going to be signed and
/// sends it to each participant with all the commitments collected.
struct MsgSigningPackage {
    /// The message to be signed: `frost::SigningPackage.message`
    message: Vec<u8>,
    /// The collected commitments for each signer as a hashmap of
    /// unique participant identifiers: `frost::SigningPackage.signing_commitments`
    ///
    /// Signing packages that contain duplicate or missing `ParticipantID`s are invalid.
    signing_commitments: HashMap<ParticipantID, SigningCommitments>,
}

/// Each signer sends their signatures to the aggregator who is going to collect them
///  and generate a final spend signature.
struct MsgSignatureShare {
     /// This participant's signature over the message:
     ///  `frost::SignatureShare.signature`
    signature: frost::Scalar,
}

/// The final signature is broadcasted by the aggregator to any participant.
struct MsgFinalSignature {
    /// The aggregated group commitment: `Signature<SpendAuth>.r_bytes` returned by `frost::aggregate`
    group_commitment: jubjub::AffinePoint,
    /// A plain Schnorr signature created by summing all the signature shares:
    /// `Signature<SpendAuth>.s_bytes` returned by `frost::aggregate`
    schnorr_signature: frost::Scalar,
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

`Scalar` is a an alias for `jubjub::Fr`. We use `Scalar::to_bytes` to get a 32-byte little-endian canonical representation. See https://github.com/zkcrypto/bls12_381/blob/main/src/scalar.rs#L252

#### `AffinePoint`

Much of the math in FROST is done using `jubjub::ExtendedPoint`. But for message exchange `jubjub::AffinePoint`s are a better choice, as their byte representation is smaller.

Conversion from one type to the other is trivial:

https://docs.rs/jubjub/0.6.0/jubjub/struct.AffinePoint.html#impl-From%3CExtendedPoint%3E
https://docs.rs/jubjub/0.6.0/jubjub/struct.ExtendedPoint.html#impl-From%3CAffinePoint%3E

We use `AffinePoint::to_bytes` to get a 32-byte little-endian canonical representation. See https://github.com/zkcrypto/jubjub/blob/main/src/lib.rs#L443

### Payload

Payload part of the message is variable in size and depends on message type.

#### `MsgDealerBroadcast`

Bytes  | Field name  | Data type
-------|-------------|-----------
32     | secret_key  | Scalar
32     | commitments | AffinePoint
32+32  | group_public| GroupPublic

#### `MsgCommitments`

Bytes   | Field name | Data type
--------|------------|-----------
32+32   | commitment | Commitment

#### `MsgSigningPackage`

Bytes                  | Field name     | Data type
-----------------------|----------------|-----------
1                      | participants   | u8
(1+32+32)*participants | commitments    | HashMap<ParticipantID, Commitment>
8                      | message_length | u64
message_length         | message        | Vec<u8>

#### `SignatureShare`

Bytes | Field name | Data type
------|------------|-----------
32    | signature  | Scalar

#### `MsgFinalSignature`

Bytes | Field name       | Data type
------|------------------|-----------
32+32 | final_signature  | FinalSignature

## Not included

The following are a few things this RFC is not considering:

- After the dealer sends the initial `MsgDealerBroadcast` to all the participants, the aggregator must wait for signers to send the second message `MsgCommitments`. There is no timeout for this but only after the aggregator received all the commitments the process can continue. These restrictions and event waiting are not detailed in this RFC.
- This implementation considers not only communications between computer devices in the internet but allows the process to be done by other channels, the lack of timers can result in participants waiting forever for a message. It is the participants business to deal with this and other similars.
- The RFC does not describe a Service but just message structure and serialization.
- Messages larger than 4 GB are not supported on 32-bit platforms.
- Implementations should validate that message lengths are lower than protocol-specific maximum length, then allocate message memory.

## Testing plan

- Create a happy path unit test similar to https://github.com/ZcashFoundation/redjubjub/blob/frost-messages/tests/frost.rs#L7 and:
  - Make messages on each step.
  - Simulate send/receive.
  - Test round trip serialization/deserialization on each message.
- Create property tests for each message.
