# Importing and General Information

## Including `frost-ristretto255`

Add to your `Cargo.toml` file:

```
[dependencies]
frost-ristretto255 = "0.6.0"
```

## Handling errors

Most crate functions mentioned below return `Result`s with
[`Error`](https://docs.rs/frost-ristretto255/latest/frost_ristretto255/type.Error.html)s.
All errors should be considered fatal and should lead to aborting the key
generation or signing procedure.

## Serializing structures

FROST is a distributed protocol and thus it requires sending messages between
participants. While the ZF FROST library does not handle communication, it can
help with serialization by activating the `serde` feature. When it is enabled,
you can use [serde](https://serde.rs/) to serialize any structure that needs
to be transmitted. Import example:

```
[dependencies]
frost-ristretto255 = { version = "0.6.0", features = ["serde"] }
```

Note that serde usage is optional. Applications can use different encodings, and
to suppor that, all structures that need to be transmitted have public getters
and `new()`  methods allowing the application to encode and decode them as it
wishes. (Note that fields like `Scalar` and `Element` do have standard byte
string encodings; the application can encode those byte strings as it wishes,
as well the structure themselves and things like maps and lists.)
