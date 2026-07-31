# Contribution architecture

## Recommended boundary

The proposal is split into three layers.

### 1. Generic `frost-hd` protocol

This layer owns only:

- canonical, typed derivation paths;
- application/network/purpose domain separation;
- deterministic edge KDF and retry rules;
- additive transformation of `KeyPackage` and `PublicKeyPackage`;
- non-signable root wrappers;
- security documentation and vectors.

It is generic over `C: frost_core::Ciphersuite` and an explicit
`P: DerivationProfile<C>`. There is no blanket profile for all ciphersuites.
This prevents the crate from silently claiming compatibility with suites whose
key normalization or signing semantics are not linear under persistent tweaks.

The implementation follows the existing `frost-rerandomized` precedent by
using `frost-core/internals`. No raw secret scalar is exposed through the
public API.

### 2. Reviewed ciphersuite profile

A profile defines:

```text
P.ID
P.hash_to_scalar(input) -> Scalar<C>
```

The profile ID is included in every context and edge transcript. Changing the
profile ID or mapping creates a different key family.

The research tests use domain-separated `C::H1` profiles for Ed25519,
Ristretto255, and ordinary secp256k1. These are explicit test profiles, not a
blanket production claim. Maintainers should decide whether reviewed profiles
use:

1. a dedicated `HHD` ciphersuite function;
2. a standard ciphersuite-specific hash-to-field mapping;
3. domain-separated `C::H1` after cryptographic review.

An x-only Taproot profile requires separate treatment of normalization and
tweak ordering. It is deliberately not instantiated by the generic tests.

### 3. Blockchain and application adapters

Solana adapters may Base58-encode a derived Ed25519 joint public key. They must
not claim SLIP-0010 compatibility.

Bitcoin adapters may define BIP32 xpub fields, BIP340 parity normalization,
BIP341 Taproot tweak ordering, descriptors, and BIP32 conformance vectors.
Those rules remain outside the generic protocol.

Application path allocation, backups, scanning, high-water marks, and policy
are also outside `frost-hd`.

## Why not put everything in `frost-core`

Persistent wallet derivation is a broader protocol than FROST signing. A
separate crate limits the API and misuse surface while reusing existing package
abstractions. A minimal core primitive remains an alternative if maintainers
want additive package tweaking shared by `frost-rerandomized`, Taproot, and HD
derivation.
