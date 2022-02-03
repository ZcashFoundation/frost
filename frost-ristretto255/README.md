An implementation of Schnorr signatures on the Ristretto group for both single and threshold numbers
of signers (FROST).

In addition to the `Signature`, `SigningKey`, `VerificationKey` types, the library also provides
`VerificationKeyBytes`, a [refinement] of a `[u8; 32]` indicating that bytes represent an encoding
of a verification key. This allows the `VerificationKey` type to cache verification checks related to
the verification key encoding.

## Examples

Creating a `Signature` with a single signer, serializing and deserializing it, and verifying the
signature:

```rust
# use std::convert::TryFrom;
use rand::thread_rng;
use frost_ristretto255::*;

let msg = b"Hello!";

// Generate a secret key and sign the message
let sk = SigningKey::new(thread_rng());
let sig = sk.sign(thread_rng(), msg);

// Types can be converted to raw byte arrays using From/Into
let sig_bytes: [u8; 64] = sig.into();
let pk_bytes: [u8; 32] = VerificationKey::from(&sk).into();

// Deserialize and verify the signature.
let sig: Signature = sig_bytes.into();

assert!(
    VerificationKey::try_from(pk_bytes)
        .and_then(|pk| pk.verify(msg, &sig))
        .is_ok()
);
```

## docs

```shell,no_run
cargo doc --features "nightly" --open
```

[redjubjub]: https://zips.z.cash/protocol/protocol.pdf#concretereddsa
[refinement]: https://en.wikipedia.org/wiki/Refinement_type
