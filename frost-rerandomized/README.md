# FROST (Flexible Round-Optimised Schnorr Threshold signatures) Rerandomized

A ciphersuite-generic implementation of [Re-Randomized
FROST](https://eprint.iacr.org/2024/436), which allows creating signatures using
FROST under re-randomized keys.

## Usage

`frost-rerandomized` is similar to `frost-core`, but provides different
`sign()` and `aggregate()` functions adding support for re-randomized signatures.

Currently, the main ciphersuite crates do not re-expose the rerandomization
functions; if you want to use this functionality, you will need to use this
crate parametrized with the chosen ciphersuite. The exception are the Zcash
ciphersuites in [`reddsa`](https://github.com/ZcashFoundation/reddsa/) which
do expose the randomized functionality.

## Example

See ciphersuite-specific modules, e.g. the ones in [`reddsa`](https://github.com/ZcashFoundation/reddsa/).
