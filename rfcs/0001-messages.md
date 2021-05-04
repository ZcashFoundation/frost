# FROST messages

Proposes a message layout to exchange information between participants of a FROST setup.

## Motivation

Currently FROST library is complete for 2 round signatures with a dealer/aggregator setup.
This proposal is only considering that specific features, additions and upgrades will need to be made when DKG is implemented.

Assuming all participants have a FROST library available we need to define message structures in a way that data can be exchanged between participants. The proposal is a collection of data types so each side can do all the actions needed for a real life situation.

## Definitions

- `dealer`
- `aggergator`
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
// `group_public` is random data at this stage and `public_key` can be calculated
// from `secret_key`.
struct MsgDealerBroadcast {
    // The secret key as a frost::Scalar.
    secret_key: frost::Scalar,
    // Set of commitments as jubjub::ExtendedPoint using frost::Commitment wrapper.
    commitments: Vec<frost::Commitment>,
}

// Each signer participant send to the aggregator the 2 points
//  needed for commitment building.
struct MsgCommitments {
    // The hiding Point.
    hiding: jubjub::ExtendedPoint,
    // The binding Point.
    binding: jubjub::ExtendedPoint,
}

// The aggergator decide what message is going to be signed and
// send it to each participant with all the commitments collected.
struct MsgSigningPackage {
    // Consist of a [u8] and vector of commitments.
    // Commitments are a signer id and a hiding and binding point.
    signing_package: frost::SigningPackage,
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
    final_signature: Signature<SpendAuth>,
}
```
## Serialization/Deserialization

Each message struct needs to serialize to bytes representation before it is sent through the wire and must deserialize to the same struct (round trip) on the receiver side. We use `serde` and macro derivations (`Serialize` and `Deserialize`) to automatically implement where possible.

This will require deriving serde in several types defined in `frost.rs`. 
Manual implementation of serialization/deserialization will be located at a new mod `src/frost/serialize.rs`.

FROST inherit types from `jubjub` such as `Scalar`, `ExtendedPoint`, `AffinePoint`, etc. We need to decide how serialization of these types that are defined in external crates will be done (maybe with wrappers?).

## Validation

Validation is implemented to each new data type as needed. This will ensure the creation of valid messages before they are sent and right after they are received. We create a trait for this as follows:

```rust
pub trait Validate {
    fn validate(&self) -> &Self;
}
```

And we implement where needed. For example, in the header sender and receiver can't be the same:

```rust
impl Validate for Header {
    fn validate(&self) -> &Self {
        if self.sender.0 == self.receiver.0 {
            panic!("sender and receiver are the same");
        }
        self
    }
}
```

Then to create a valid `Header` we call:

```rust
let header = Validate::validate(&Header {
    ..
}).clone();
```

The receiver side will validate the header as:

```rust
msg.header.validate();
```

## Serialized Size

### Header

The `Header` part of the message is 4 bytes total:

Bytes | Field name | Data type
------|------------|-----------
1     | msg_type   | u8
1     | version    | u8
1     | sender     | u8
1     | receiver   | u8

## Primitive types

`Payload`s use data types that we need to specify first. We have 3 primitive types inside the payload messages:

`Scalar`

`Scalar` is a better name for `jubjub::Fr` and this is a `[u64; 4]` as documented in https://github.com/zkcrypto/jubjub/blob/main/src/fr.rs#L16

`Commitment`

`Commitment` is a wrapper of `jubjub::ExtendedPoint` and this is a structure with 5 `jubjub::Fq`s as defined in https://github.com/zkcrypto/jubjub/blob/main/src/lib.rs#L128-L134

Each `Fq` needed to form a `jubjub::ExtendedPoint` are `Scalar`s of `bls12_381` crate. Scalar here is `[u64; 4]` as documented in https://github.com/zkcrypto/bls12_381/blob/main/src/scalar.rs#L16

`ExtendedPoint`

`ExtendedPoint` was detailed above, it is 5 `[u64; 4]`. The total size of an `ExtendedPoint` is 1280 bytes.

## Payload

Payload part of the message is variable in size and depends on message type.

`MsgDealerBroadcast`:

Bytes | Field name | Data type
------|------------|-----------
256   | secret_key | Scalar
1280*n| commitments| [Commitment; n]

`MsgCommitments`:

`MsgSigningPackage`:

`SignatureShare`:

`MsgFinalSignature`:


## Testing plan

- Create a happy path unit test similar to https://github.com/ZcashFoundation/redjubjub/blob/frost-messages/tests/frost.rs#L7 and:
  - Make messages on each step.
  - Simulate send/receive.
  - Test round trip serialization/deserialization on each message.
- Create property tests for each message.
