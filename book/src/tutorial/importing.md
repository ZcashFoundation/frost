# Importing and General Information

## Including `frost-ristretto255`

Add to your `Cargo.toml` file:

```
[dependencies]
frost-ristretto255 = "2.0.0-rc.0"
```

## Handling errors

Most crate functions mentioned below return `Result`s with
[`Error`](https://docs.rs/frost-ristretto255/latest/frost_ristretto255/type.Error.html)s.
All errors should be considered fatal and should lead to aborting the key
generation or signing procedure.

## Serializing structures

FROST is a distributed protocol and thus it requires sending messages between
participants. While the ZF FROST library does not handle communication, it can
help with serialization in the following ways:

### Default byte-oriented serialization

With the `serialization` feature, which is enabled by default, all structs that
need to be communicated will have `serialize()` and `deserialize()` methods. The
serialization format is described in [Serialization
Format](../user/serialization.md).

### serde

Alternatively, if you would like to user another format such as JSON, you can
enable the `serde` feature (which is *not* enabled by default). When it is
enabled, you can use [serde](https://serde.rs/) to serialize any structure that
needs to be transmitted. The importing would look like:

```
[dependencies]
frost-ristretto255 = { version = "2.0.0-rc.0", features = ["serde"] }
```

Note that serde usage is optional. Applications can use different encodings, and
to support that, all structures that need to be transmitted have public getters
and `new()`  methods allowing the application to encode and decode them as it
wishes. (Note that fields like `Scalar` and `Element` do have standard byte
string encodings; the application can encode those byte strings as it wishes, as
well the structure themselves and things like maps and lists.)
