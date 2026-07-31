# Solana / Ed25519 profile

A Solana integration uses the generic protocol with the official
`FROST-ED25519-SHA512-v1` ciphersuite and an explicitly reviewed Ed25519
`DerivationProfile`.

Example application context and path policy:

```text
application = "wallet.example"
network     = "solana-mainnet"
purpose     = "receive"
path        = m/<account>/<branch>/<address>
```

The resulting joint Ed25519 public key can be Base58-encoded as a Solana
address by the application layer. Base58 is not part of `frost-hd`.

This construction is not SLIP-0010 and is not compatible with common hardened
Solana mnemonic paths such as `m/44'/501'/account'/0'`. It must be described as
a distinct FROST Ed25519 key-family protocol.
