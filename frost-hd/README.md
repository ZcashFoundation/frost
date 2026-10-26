# frost-hd

Experimental, blockchain-agnostic, **non-hardened** hierarchical key
derivation for FROST key packages.

The crate is generic over a FROST ciphersuite `C` and an explicitly reviewed
`DerivationProfile<C>`. It does not provide blanket support for every
ciphersuite.

The core transformation is:

```text
s_i' = s_i + t
Y_i' = Y_i + tG
Y'   = Y   + tG
```

A descendant signing share plus public derivation metadata reveals the
corresponding ancestor share. See [Security review notes](docs/SECURITY.md)
before evaluating this API.

This crate is research code for private review. It is not audited or
production-ready. It intentionally excludes BIP32 xpubs, Taproot wallet
policy, Solana addresses, SLIP-0010 compatibility, and hardened threshold
derivation.

## Tests

Run `cargo test -p frost-hd --locked` from the workspace root.
The suite includes serialized DKG rounds, 2-of-2, 2-of-3 and 3-of-5
child signing with every threshold-size subset, independent Ed25519
verification, malformed-input rejection and parent-share recovery.
