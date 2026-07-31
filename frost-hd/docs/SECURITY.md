# Security review notes

## Severity-defining property

The construction is intentionally related-key:

```text
parent participant share = child participant share - public cumulative tweak
```

This means the security boundary is one key family, not one child. An adversary may compromise participant A on path `/0` and participant B on path `/99/3`, normalize both shares to the same root epoch, and reach the threshold without ever compromising two shares on one child.

## Threat model

The proposal explicitly considers:

- root or child signing-share compromise;
- derivation-key disclosure and path enumeration;
- cross-path accumulation of distinct participant compromises;
- malicious root derivation-key bias and selective abort;
- inconsistent public package, path, context, or retry views;
- refresh and resharing epoch confusion;
- signer-set and identifier changes;
- root and child nonce reuse;
- rollback, duplicate path allocation, and backup loss;
- malformed and non-canonical serialization;
- zero scalar, group identity, subgroup, and cofactor edge cases;
- accidental root signing or funding;
- downgrade to a weaker family/profile version.

## Required application controls

An application using this construction must:

1. authenticate the root public package, root derivation key, context, and version;
2. reserve paths atomically and never reuse abandoned paths;
3. persist a monotonic high-water mark or equivalent allocation ledger;
4. bind path and family metadata to signing authorization;
5. separate share epochs and reject mixed-epoch signing;
6. rotate to a fresh independent DKG after a bounded number of children or any suspected compromise;
7. retain independent-DKG fallback;
8. avoid logging derivation keys and paths when they are treated as sensitive metadata.

## No production claim

The Rust code in this repository is a research prototype. It has not received an independent cryptographic audit and has not been compiled against the full upstream workspace in the current execution environment.
