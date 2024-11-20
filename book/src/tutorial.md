# Tutorial

The ZF FROST suite consists of multiple crates. `frost-core` contains
a generic implementation of the protocol, which can't be used directly
without a concrete instantiation.

The ciphersuite crates (`frost-ristretto255`, `frost-ed25519`, `frost-ed448`,
`frost-p256`, `frost-secp256k1-evm` and `frost-secp256k1-tr`) provide ciphersuites
to use with `frost-core`, but also re-expose the `frost-core` functions without
generics. If you will only use a single ciphersuite, then we recommend
using those functions, and this tutorial will follow this approach.
If you need to support multiple ciphersuites then feel free to use
`frost-core` along with the ciphersuite types.

This tutorial will use the `frost-ristretto255` crate, but changing
to another ciphersuite should be a matter of simply changing the import.

