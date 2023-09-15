# Serialization Format

With the `serialization` feature, which is enabled by default, all structs that
need to communicated will have `serialize()` and `deserialize()` methods.

The format is basically the `serde` encoding of the structs using the
[`postcard`](https://docs.rs/postcard/latest/postcard/) crate.

- Integers are encoded in [varint
  format](https://postcard.jamesmunns.com/wire-format#varint-encoded-integers)
- Fixed-size byte arrays are encoded as-is (e.g. scalars, elements)
  - Note that the encoding of scalars and elements are defined by the
    ciphersuites.
- Variable-size byte arrays are encoded with a length prefix (varint-encoded)
  and the array as-is (e.g. the message)
- Maps are encoded as the varint-encoded item count, followed by concatenated
  item encodings.
- Ciphersuite IDs are encoded as the 4-byte CRC-32 of the ID string.
- Structs are encoded as the concatenation of the encodings of its items.

For example, the following Signing Package:

- Commitments (map):
    - Identifier (byte array): `2a00000000000000000000000000000000000000000000000000000000000000`
    - Signing Commitments:
      - Hiding (byte array): `e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76`
      - Bindng (byte array): `6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919`
      - Ciphersuite ID: `"FROST(ristretto255, SHA-512)"`
- Message (variable size byte array): `68656c6c6f20776f726c64` (`"hello world"` in UTF-8)
- Ciphersuite ID (4 bytes): `"FROST(ristretto255, SHA-512)"`

Is encoded as

```
012a000000000000000000000000000000000000000000000000000000000000
00e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d
766a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b9
19e6811b690b68656c6c6f20776f726c64e6811b69
```

- `01`: the length of the map
- `2a00000000000000000000000000000000000000000000000000000000000000`: the identifier
- `e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76`: the hinding commitment
- `6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919`: the binding commitment
- `e6811b69`: the ciphersuite ID of the SigningCommitments, CRC-32 of "FROST(ristretto255, SHA-512)"
- `0b`: the length of the message
- `68656c6c6f20776f726c64`: the message
- `e6811b69`: the ciphersuite ID of the SigningPackage, CRC-32 of "FROST(ristretto255, SHA-512)"

```admonish note
The ciphersuite ID is encoded multiple times in this case because `SigningPackage` includes
`SigningCommitments`, which also need to be communicated in Round 1 and thus also encodes
its ciphersuite ID. This is the only instance where this happens.
```

## Test Vectors

Check the
[`snapshots`](https://github.com/search?q=repo%3AZcashFoundation%2Ffrost+path%3Asnapshots&type=code)
files in each ciphersuite crate for test vectors.