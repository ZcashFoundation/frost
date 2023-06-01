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

## Generating key shares with a trusted dealer

![Diagram of Trusted Dealer Key Generation, illustrating what is explained in the text](tutorial/tkg.png)

To generate the key shares, the dealer calls
[`generate_with_dealer()`](https://docs.rs/frost-ristretto255/latest/frost_ristretto255/keys/fn.generate_with_dealer.html).
It returns a `HashMap` mapping the (automatically generated) `Identifier`s to
their respective `SecretShare`s, and a `PublicKeyPackage` which contains the
`VerifyingShare` for each participant and the group public key (`VerifyingKey`).

TODO: insert code snippet

Each `SecretShare` must then be sent via an [**authenticated** and
**confidential** channel ](https://frost.zfnd.org/terminology.html#peer-to-peer-channel)for each participant, who verify the
package to obtain a `KeyPackage` which contains their signing share,
verifying share and group verifying key.

TODO: insert code snippet

```admonish info
Currently there is no way to specify which identifiers to use. This will
likely be supported in the future.
```

```admonish info
Which encoding to use to transmit the `SecretShare` is up for the developer.
Note that specific types (Scalars, Elements) do have a standardized encoding.
Also note that `serde` support will be added in the future to offer a default
method for encoding.

The same applies to `KeyPackage`.
```

```admonish danger
Which [**authenticated** and **confidential** channel](https://frost.zfnd.org/terminology.html#peer-to-peer-channel) to use is up to the
application. Some examples:

- Manually require the dealer to sent the `SecretShare`s to the
  partipants using some secure messenger such as Signal;
- Use a TLS connection, authenticating the server with a certificate
  and the client with some user/password or another suitable authentication
  mechanism;

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

![Diagram of Signing, illustrating what is explained in the text](tutorial/signing.png)

TODO: explain


## Verifying signatures

TODO: explain

## DKG

(TODO: will probably have its own page)