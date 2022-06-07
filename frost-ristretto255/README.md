An implementation of Schnorr signatures on the Ristretto group for both single and threshold numbers
of signers (FROST).

## Examples

Creating a `Signature` with a single signer, serializing and deserializing it, and verifying the
signature:

```rust
use rand::thread_rng;
use frost_ristretto255::*;

let msg = b"Hello!";

// Generate a secret key and sign the message
let sk = SigningKey::new(thread_rng());
let sig = sk.sign(thread_rng(), msg);

// Types can be converted to raw byte arrays using `from_bytes`/`to_bytes`
let sig_bytes = sig.to_bytes();
let pk_bytes = VerifyingKey::from(&sk).to_bytes();

// Deserialize and verify the signature.
let sig = Signature::from_bytes(sig_bytes)?;

assert!(
    VerifyingKey::from_bytes(pk_bytes)
        .and_then(|pk| pk.verify(msg, &sig))
        .is_ok()
);
# Ok::<(), Error>(())
```
