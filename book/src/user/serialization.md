# Serialization Format

With the `serialization` feature, which is enabled by default, all structs that
need to communicated will have `serialize()` and `deserialize()` methods.

The format is basically the `serde` encoding of the structs using the
[`postcard`](https://docs.rs/postcard/latest/postcard/) crate. But since this is
an implementation detail, we describe the format as follows:

- Integers are encoded in [varint
  format](https://postcard.jamesmunns.com/wire-format#varint-encoded-integers)
- Fixed-size byte arrays are encoded as-is (e.g. scalars, elements)
  - Note that the encoding of scalars and elements are defined by the
    ciphersuites.
- Variable-size byte arrays are encoded with a length prefix (varint-encoded)
  and the array as-is (e.g. the message)
- Maps are encoded as the varint-encoded item count, followed by concatenated
  item encodings.
- Structs are encoded as the concatenation of the encodings of its items, with
  a Header struct as the first item, which contains the format version (a u8)
  and the ciphersuite ID.
  - The format currently described is identified by the constant 0.
  - Ciphersuite IDs are encoded as the 4-byte CRC-32 of the ID string (the
    constant Ciphersuite::ID, which for default ciphersuites is the contextString
    of the ciphersuite, per the FROST spec).

For example, the following Signing Package:

- Header (map):
  - Version (u8): 0
  - Ciphersuite ID (4 bytes): CRC-32 of `FROST-RISTRETTO255-SHA512-v1`
- Commitments (map):
  - Identifier (byte array): `2a00000000000000000000000000000000000000000000000000000000000000`
  - Signing Commitments:
    - Hiding (byte array): `e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76`
    - Bindng (byte array): `6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919`
    - Ciphersuite ID (4 bytes): CRC-32 of `FROST-RISTRETTO255-SHA512-v1`
- Message (variable size byte array): `68656c6c6f20776f726c64` (`"hello world"` in UTF-8)

Is encoded as

```
00d76ecff5012a00000000000000000000000000000000000000000000000000
00000000000000d76ecff5e2f2ae0a6abc4e71a884a961c500515f58e30b6aa5
82dd8db6a65945e08d2d766a493210f7499cd17fecb510ae0cea23a110e8d5b9
01f8acadd3095c73a3b9190b68656c6c6f20776f726c64
```

- `00`: the version of the format
- `d76ecff5`: the ciphersuite ID of the SigningPackage; CRC-32 of `FROST-RISTRETTO255-SHA512-v1`
- `01`: the length of the map
- `2a00000000000000000000000000000000000000000000000000000000000000`: the identifier
- `d76ecff5`: the ciphersuite ID of the SigningCommitments; CRC-32 of `FROST-RISTRETTO255-SHA512-v1`
- `e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76`: the hinding commitment
- `6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919`: the binding commitment
- `0b`: the length of the message
- `68656c6c6f20776f726c64`: the message

```admonish note
The ciphersuite ID is encoded multiple times in this case because `SigningPackage` includes
`SigningCommitments`, which also need to be communicated in Round 1 and thus also encodes
its ciphersuite ID. This is the only instance where this happens.
```

## Test Vectors

Check the
[`snapshots`](https://github.com/search?q=repo%3AZcashFoundation%2Ffrost+path%3Asnapshots&type=code)
files in each ciphersuite crate for test vectors.