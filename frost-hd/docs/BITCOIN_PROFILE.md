# Bitcoin / secp256k1 profile

The generic protocol can derive ordinary FROST secp256k1 key packages through
an explicitly reviewed secp256k1 `DerivationProfile`. This does not embed
Bitcoin wallet policy and is not BIP32 compatibility by itself.

Exact Bitcoin interoperability requires a separate adapter defining:

- BIP32 non-hardened CKD and chain-code semantics, when exact compatibility is
  a goal;
- xpub depth, parent fingerprint, child number, and version bytes;
- BIP340 x-only parity normalization;
- ordering relative to the BIP341 Taproot tweak;
- descriptor serialization and conformance vectors.

The current generic crate does not instantiate `frost-secp256k1-tr`. X-only
normalization and Taproot tweak ordering require their own profile and proof.
