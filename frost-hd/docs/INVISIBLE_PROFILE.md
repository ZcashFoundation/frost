# Invisible profile: separate from the generic protocol

Invisible uses FROST Ed25519 on Solana. Its application profile would set, for example:

```text
application = "exchange.invisible"
network     = "solana-mainnet"
purpose     = "lp-reimbursement"
path        = m/<position>/<refill-epoch>/<shard>
```

The derived Ed25519 joint public key may be Base58-encoded as a Solana address by Invisible. Base58 and Solana address handling do not belong in `frost-hd`.

## Critical 2-of-2 implication

If a TEE receives a derived client child share and knows the public cumulative tweak, it can compute the client's parent share. Combined with the TEE side of the 2-of-2 family, this gives the TEE control of the entire bounded family. The construction therefore reduces DKG operations but does not preserve child-level cryptographic separation after delegation.

## Pilot constraints

- no global protocol root;
- one root per bounded refill batch or short operational epoch;
- root never funded;
- initially 16 children, hard cap 32;
- atomic range reservation and sealed high-water mark;
- tombstone abandoned indices; no path reuse;
- rotate through a fresh independent DKG;
- keep independent-DKG fallback;
- do not deploy in V0 without a cryptographic review and end-to-end sealed-state tests.
