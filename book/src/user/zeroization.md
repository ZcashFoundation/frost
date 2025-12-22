# Zeroization

The ZF FROST crates have limited best-effort support at zeroization. The
top-level structs (`KeyPackage`, `SecretShare`, etc.) implement the
`Zeroize` and `ZeroizeOnDrop` from the `zeroize` crate. This means that
when they are dropped they are cleared from memory.

However, be advised that the user is responsible for everything else. For
example, if you serialize the structs, then you will be responsible for
zeroizing the serialized buffers, which _will_ contain secrets.

Additionally, if you extract the secret fields (e.g. `KeyPackage::signing_share()`)
they you are also responsible for zeroizing them if you make a copy, since
the inner types do not implement `ZeroizeOnDrop` (though most of them do
implement `Zeroize` so you can call `zeroize()` manually).
