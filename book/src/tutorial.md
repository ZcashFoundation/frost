# Tutorial

The ZF FROST suite consists of multiple crates. `frost-core` contains
a generic implementation of the protocol, which can't be used directly
without a concrete instantiation.

The ciphersuite crates (`frost-ristretto255`, `frost-ed25519`, `frost-ed448`,
`frost-p256`, and `frost-secp256k1`) provide ciphersuites to use with
`frost-core`, but also re-expose the `frost-core` functions without
generics. If you will only use a single ciphersuite, then we recommend
using those functions, and this tutorial will follow this approach.
If you need to support multiple ciphersuites then feel free to use
`frost-core` along with the ciphersuite types.

This tutorial will use the `frost-ristretto255` crate, but changing
to another ciphersuite should be a matter of simply changing the import.

## Including `frost-ristretto255`

Add to your `Cargo.toml` file:

```
[dependencies]
frost-ristretto255 = "0.3.0"
```

## Handling errors

Most crate functions mentioned below return `Result`s with
[`Error`](https://docs.rs/frost-ristretto255/latest/frost_ristretto255/type.Error.html)s.
All errors should be considered fatal and should lead to aborting the key
generation or signing procedure.

## Serializing structures

FROST is a distributed protocol and thus it requires sending messages between
participants. However, the ZF FROST library does not handle communication nor
encoding, which is the application's responsibility. For this reason, all
structures that need to be transmitted have public fields allowing the
application to encode and decode them as it wishes. (Note that fields like
`Scalar` and `Element` do have standard encodings; only the serialization of the
structure itself and things like maps and lists need to be handled by the
application.)

The ZF FROST library will also support `serde` in the future, which will make
this process simpler.


## Generating key shares with a trusted dealer

The diagram below shows the trusted dealer key generation process. Dashed lines
represent data being sent through an [authenticated and confidential communication
channel](https://frost.zfnd.org/terminology.html#peer-to-peer-channel).

![Diagram of Trusted Dealer Key Generation, illustrating what is explained in the text](tutorial/tkg.png)

To generate the key shares, the dealer calls
[`generate_with_dealer()`](https://docs.rs/frost-ristretto255/latest/frost_ristretto255/keys/fn.generate_with_dealer.html).
It returns a `HashMap` mapping the (automatically generated) `Identifier`s to
their respective `SecretShare`s, and a `PublicKeyPackage` which contains the
`VerifyingShare` for each participant and the group public key (`VerifyingKey`).

```rust,no_run,noplayground
{{#include ../../frost-ristretto255/README.md:tkg_gen}}
```

Each `SecretShare` must then be sent via an [**authenticated** and
**confidential** channel
](https://frost.zfnd.org/terminology.html#peer-to-peer-channel) for each
participant, who must verify the package to obtain a `KeyPackage` which contains
their signing share, verifying share and group verifying key. This is done with
[`KeyPackage::try_from()`](https://docs.rs/frost-core/latest/frost_core/frost/keys/struct.KeyPackage.html#method.try_from):

```rust,no_run,noplayground
{{#include ../../frost-ristretto255/README.md:tkg_verify}}
```

```admonish info
Currently there is no way to specify which identifiers to use. This will
likely be supported in the future.

[More information on how to handle Identifiers](https://frost.zfnd.org/terminology.html#identifier).
```

```admonish danger
Which [**authenticated** and **confidential** channel](https://frost.zfnd.org/terminology.html#peer-to-peer-channel)
to use is up to the application. Some examples:

- Manually require the dealer to sent the `SecretShare`s to the
  partipants using some secure messenger such as Signal;
- Use a TLS connection, authenticating the server with a certificate
  and the client with some user/password or another suitable authentication
  mechanism;

Refer to the [Terminology page](https://frost.zfnd.org/terminology.html#peer-to-peer-channel)
for more details.

Failure of using a **confidential** channel may lead to the shares being
stolen and possibly allowing signature forgeries if a threshold number of
them are stolen.

Failure of using an **authenticated** channel may lead to shares being
sent to the wrong person, possibly allowing unintended parties
to generate signatures.
```

```admonish danger
The `SecretPackage` contents must be stored securely. For example:

- Make sure other users in the system can't read it;
- If possible, use the OS secure storage such that the package
  contents can only be opened with the user's password or biometrics.
```

```admonish warning
The participants may wish to not fully trust the dealer. While **the dealer
has access to the original secret and can forge signatures
by simply using the secret to sign** (and this can't be
possibly avoided with this method; use Distributed Key Generation
if that's an issue), the dealer could also tamper with the `SecretShare`s
in a way that the participants will never be able to generate a valid
signature in the future (denial of service). Participants can detect
such tampering by comparing the `VerifiableSecretSharingCommitment`
values from their `SecretShare`s (either by some manual process, or
by using a [broadcast channel](https://frost.zfnd.org/terminology.html#broadcast-channel))
to make sure they are all equal.
```

## Signing

The diagram below shows the signing process. Dashed lines represent data being
sent through an [authenticated communication
channel](https://frost.zfnd.org/terminology.html#peer-to-peer-channel).

![Diagram of Signing, illustrating what is explained in the text](tutorial/signing.png)

### Coordinator, Round 1

To sign, the
[Coordinator](file:///home/conrado/zfnd/frost/book/book/frost.html#signing) must
select which participants are going to generate the signature, and must signal
to start the process. This needs to be done by library user and will depend on
the communication channel being used.

### Participants, Round 1

Each selected participant will then generate the nonces (a `SigningNonces`) and
their commitments (a `SigningCommitments`) by calling
[`round1::commit()`](https://docs.rs/frost-ristretto255/latest/frost_ristretto255/round1/fn.commit.html):

```rust,no_run,noplayground
{{#include ../../frost-ristretto255/README.md:round1_commit}}
```

The `SigningNonces` must be kept by the participant to use in Round 2, while the
`SigningCommitments` must be sent to the Coordinator using an [authenticated
channel](https://frost.zfnd.org/terminology.html#broadcast-channel).

### Coordinator, Round 2

The Coordinator will get all `SigningCommitments` from the participants and the
message to be signed, and then build a `SigningPackage` by calling
[`SigningPackage::new()`](https://docs.rs/frost-core/latest/frost_core/frost/struct.SigningPackage.html#method.new).

```rust,no_run,noplayground
{{#include ../../frost-ristretto255/README.md:round2_package}}
```

The `SigningPackage` must then be sent to all the participants using an
[authenticated
channel](https://frost.zfnd.org/terminology.html#peer-to-peer-channel). (Of course,
if the message is confidential, then the channel must also be confidential.)

```admonish warning
In all the main FROST ciphersuites, the entire message must
be sent to participants. In some cases, where the message is too big, it may be
necessary to send a hash of the message instead. We strongly suggest creating a
specific ciphersuite for this, and not just sending the hash as if it were the
message. For reference, see [how RFC 8032 handles
"pre-hashing"](https://datatracker.ietf.org/doc/html/rfc8032).
```

### Participants, Round 2

Upon receiving the `SigningPackage`, each participant will then produce their
signature share using their `KeyPackage` from the key generation process and
their `SigningNonces` from Round 1, by calling
[`round2::sign()`](https://docs.rs/frost-ristretto255/latest/frost_ristretto255/round2/fn.sign.html):

```rust,no_run,noplayground
{{#include ../../frost-ristretto255/README.md:round2_sign}}
```

The resulting `SignatureShare` must then be sent back to the Coordinator using
an [authenticated
channel](https://frost.zfnd.org/terminology.html#peer-to-peer-channel).

```admonish important
In most applications, it is important that the participant must be aware of what
they are signing. Thus the application should show the message to the
participant and obtain their consent to proceed before producing the signature
share.
```

### Coordinator, Aggregate

Upon receiving the `SignatureShare`s from the participants, the Coordinator can
finally produce the final signature by calling
[`aggregate()`](https://docs.rs/frost-ristretto255/latest/frost_ristretto255/fn.aggregate.html)
with the same `SigningPackage` sent to the participants and the
`PublicKeyPackage` from the key generation (which is used to validate each
`SignatureShare`).

```rust,no_run,noplayground
{{#include ../../frost-ristretto255/README.md:aggregate}}
```

The returned signature, a `Signature`, will be a valid signature for the message
chosen in Round 2 for the group verifying key in the `PublicKeyPackage`.

```admonish note
FROST supports identifiable abort: if a participant misbehaves and produces an
invalid signature share, then aggregation will fail and the returned error
will have the identifier of the misbehaving participant. (If multiple participants
misbehave, only the first one detected will be returned.)

What should be done in that case is up to the application. The misbehaving participant
could be excluded from future signing sessions, for example.
```


## Verifying signatures

The Coordinator could verify the signature with:

```rust,no_run,noplayground
{{#include ../../frost-ristretto255/README.md:verify}}
```

(There is no need for the Coordinator to verify the signature since that already
happens inside `aggregate()`. This just shows how the signature can be
verified.)
