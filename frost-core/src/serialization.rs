//! Serialization support.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt::Formatter;
use core::marker::PhantomData;

#[cfg(feature = "serde")]
use crate::keys::PublicKeyPackage;
use crate::keys::VerifyingShare;
use crate::{Ciphersuite, FieldError, Header, Identifier, VerifyingKey};

use crate::{Element, Error, Field, Group};

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "internals", visibility::make(pub))]
#[cfg_attr(docsrs, doc(cfg(feature = "internals")))]
/// Helper struct to serialize a Scalar.
pub(crate) struct SerializableScalar<C: Ciphersuite>(
    pub <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar,
);

impl<C> SerializableScalar<C>
where
    C: Ciphersuite,
{
    /// Serialize a Scalar.
    pub fn serialize(&self) -> Vec<u8> {
        <<C::Group as Group>::Field>::serialize(&self.0)
            .as_ref()
            .to_vec()
    }

    /// Deserialize a Scalar from a serialized buffer.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error<C>> {
        let serialized: <<C::Group as Group>::Field as Field>::Serialization =
            bytes.try_into().map_err(|_| FieldError::MalformedScalar)?;
        let scalar = <<C::Group as Group>::Field>::deserialize(&serialized)?;
        Ok(Self(scalar))
    }
}

#[cfg(feature = "serde")]
impl<C> serde::Serialize for SerializableScalar<C>
where
    C: Ciphersuite,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serialized = <<C as Ciphersuite>::Group as Group>::Field::serialize(&self.0);
        serdect::array::serialize_hex_lower_or_bin(&serialized.as_ref(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, C> serde::Deserialize<'de> for SerializableScalar<C>
where
    C: Ciphersuite,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Get serialization buffer from the zero scalar
        let zero = <<C::Group as Group>::Field as Field>::zero();
        let mut serialization = <<C::Group as Group>::Field as Field>::serialize(&zero);

        serdect::array::deserialize_hex_or_bin(serialization.as_mut(), deserializer)?;

        <<C as Ciphersuite>::Group as Group>::Field::deserialize(&serialization)
            .map(|scalar| Self(scalar))
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SerializableElement<C: Ciphersuite>(pub(crate) Element<C>);

impl<C> SerializableElement<C>
where
    C: Ciphersuite,
{
    /// Serialize an Element. Returns an error if it's the identity.
    pub fn serialize(&self) -> Result<Vec<u8>, Error<C>> {
        Ok(<C::Group as Group>::serialize(&self.0)?.as_ref().to_vec())
    }

    /// Deserialize an Element. Returns an error if it's malformed or is the
    /// identity.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error<C>> {
        let serialized: <C::Group as Group>::Serialization =
            bytes.try_into().map_err(|_| FieldError::MalformedScalar)?;
        let scalar = <C::Group as Group>::deserialize(&serialized)?;
        Ok(Self(scalar))
    }
}

#[cfg(feature = "serde")]
impl<C> serde::Serialize for SerializableElement<C>
where
    C: Ciphersuite,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serialized =
            <C::Group as Group>::serialize(&self.0).map_err(serde::ser::Error::custom)?;
        serdect::array::serialize_hex_lower_or_bin(&serialized.as_ref(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, C> serde::Deserialize<'de> for SerializableElement<C>
where
    C: Ciphersuite,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Get serialization buffer from the generator
        let generator = <C::Group>::generator();
        let mut serialization =
            <C::Group>::serialize(&generator).expect("serializing the generator always works");

        serdect::array::deserialize_hex_or_bin(serialization.as_mut(), deserializer)?;

        <C::Group as Group>::deserialize(&serialization)
            .map(|element| Self(element))
            .map_err(serde::de::Error::custom)
    }
}

// The short 4-byte ID. Derived as the CRC-32 of the UTF-8
// encoded ID in big endian format.
#[cfg(feature = "serde")]
const fn short_id<C>() -> [u8; 4]
where
    C: Ciphersuite,
{
    const_crc32::crc32(C::ID.as_bytes()).to_be_bytes()
}

/// Serialize a placeholder ciphersuite field with the ciphersuite ID string.
#[cfg(feature = "serde")]
pub(crate) fn ciphersuite_serialize<S, C>(_: &(), s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    C: Ciphersuite,
{
    use serde::Serialize;

    if s.is_human_readable() {
        C::ID.serialize(s)
    } else {
        serde::Serialize::serialize(&short_id::<C>(), s)
    }
}

/// Deserialize a placeholder ciphersuite field, checking if it's the ciphersuite ID string.
#[cfg(feature = "serde")]
pub(crate) fn ciphersuite_deserialize<'de, D, C>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
    C: Ciphersuite,
{
    if deserializer.is_human_readable() {
        let s: alloc::string::String = serde::de::Deserialize::deserialize(deserializer)?;
        if s != C::ID {
            Err(serde::de::Error::custom("wrong ciphersuite"))
        } else {
            Ok(())
        }
    } else {
        let buffer: [u8; 4] = serde::de::Deserialize::deserialize(deserializer)?;
        if buffer != short_id::<C>() {
            Err(serde::de::Error::custom("wrong ciphersuite"))
        } else {
            Ok(())
        }
    }
}

/// Deserialize a version. For now, since there is a single version 0,
/// simply validate if it's 0.
#[cfg(feature = "serde")]
pub(crate) fn version_deserialize<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let version: u8 = serde::de::Deserialize::deserialize(deserializer)?;
    if version != 0 {
        Err(serde::de::Error::custom(
            "wrong format version, only 0 supported",
        ))
    } else {
        Ok(version)
    }
}

// Default byte-oriented serialization for structs that need to be communicated.
//
// Note that we still manually implement these methods in each applicable type,
// instead of making these traits `pub` and asking users to import the traits.
// The reason is that ciphersuite traits would need to re-export these traits,
// parametrized with the ciphersuite, but trait aliases are not currently
// supported: <https://github.com/rust-lang/rust/issues/41517>

#[cfg(feature = "serialization")]
pub(crate) trait Serialize<C: Ciphersuite> {
    /// Serialize the struct into a Vec.
    fn serialize(&self) -> Result<Vec<u8>, Error<C>>;
}

#[cfg(feature = "serialization")]
pub(crate) trait Deserialize<C: Ciphersuite> {
    /// Deserialize the struct from a slice of bytes.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error<C>>
    where
        Self: core::marker::Sized;
}

#[cfg(feature = "serialization")]
impl<T: serde::Serialize, C: Ciphersuite> Serialize<C> for T {
    fn serialize(&self) -> Result<Vec<u8>, Error<C>> {
        postcard::to_allocvec(self).map_err(|_| Error::SerializationError)
    }
}

#[cfg(feature = "serialization")]
impl<T: for<'de> serde::Deserialize<'de>, C: Ciphersuite> Deserialize<C> for T {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error<C>> {
        postcard::from_bytes(bytes).map_err(|_| Error::DeserializationError)
    }
}

/// Custom deserializer for PublicKeyPackage, which allows a non-existing
/// `min_signers` field for the `postcard` encoding.
#[cfg(feature = "serde")]
impl<'de, C: Ciphersuite> serde::Deserialize<'de> for PublicKeyPackage<C>
where
    C: Ciphersuite,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt;

        // The following are copied from the `serde::Deserialize` derive, and
        // are required to support `visit_map()` which in turn is required for
        // `serde_json`.

        enum Field {
            Field0,
            Field1,
            Field2,
            Field3,
        }

        struct FieldVisitor;

        impl<'de> serde::de::Visitor<'de> for FieldVisitor {
            type Value = Field;

            fn expecting(&self, __formatter: &mut Formatter) -> fmt::Result {
                Formatter::write_str(__formatter, "field identifier")
            }

            fn visit_u64<__E>(self, __value: u64) -> Result<Self::Value, __E>
            where
                __E: serde::de::Error,
            {
                match __value {
                    0u64 => Ok(Field::Field0),
                    1u64 => Ok(Field::Field1),
                    2u64 => Ok(Field::Field2),
                    3u64 => Ok(Field::Field3),
                    _ => Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Unsigned(__value),
                        &"field index 0 <= i < 4",
                    )),
                }
            }

            fn visit_str<__E>(self, __value: &str) -> Result<Self::Value, __E>
            where
                __E: serde::de::Error,
            {
                match __value {
                    "header" => Ok(Field::Field0),
                    "verifying_shares" => Ok(Field::Field1),
                    "verifying_key" => Ok(Field::Field2),
                    "min_signers" => Ok(Field::Field3),
                    _ => Err(serde::de::Error::unknown_field(__value, FIELDS)),
                }
            }

            fn visit_bytes<__E>(self, __value: &[u8]) -> Result<Self::Value, __E>
            where
                __E: serde::de::Error,
            {
                match __value {
                    b"header" => Ok(Field::Field0),
                    b"verifying_shares" => Ok(Field::Field1),
                    b"verifying_key" => Ok(Field::Field2),
                    b"min_signers" => Ok(Field::Field3),
                    _ => {
                        let __value = &String::from_utf8_lossy(__value);
                        Err(serde::de::Error::unknown_field(__value, FIELDS))
                    }
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for Field {
            #[inline]
            fn deserialize<__D>(__deserializer: __D) -> Result<Self, __D::Error>
            where
                __D: serde::Deserializer<'de>,
            {
                serde::Deserializer::deserialize_identifier(__deserializer, FieldVisitor)
            }
        }

        struct Visitor<C> {
            marker: PhantomData<C>,
        }

        impl<'de, C: Ciphersuite> serde::de::Visitor<'de> for Visitor<C>
        where
            C: Ciphersuite,
        {
            type Value = PublicKeyPackage<C>;

            fn expecting(&self, fmt: &mut Formatter) -> std::fmt::Result {
                Formatter::write_str(fmt, "struct PublicKeyPackage")
            }

            // Postcard serializes structs as sequences, so we override
            // `visit_seq` to deserialize the struct from a sequence of elements.
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                // Read the first three fields as usual.

                let header = seq.next_element::<Header<C>>()?.ok_or_else(|| {
                    serde::de::Error::invalid_length(
                        0usize,
                        &"struct PublicKeyPackage with 4 elements",
                    )
                })?;
                let verifying_shares = seq
                    .next_element::<BTreeMap<Identifier<C>, VerifyingShare<C>>>()?
                    .ok_or_else(|| {
                        serde::de::Error::invalid_length(
                            1usize,
                            &"struct PublicKeyPackage with 4 elements",
                        )
                    })?;
                let verifying_key = seq.next_element::<VerifyingKey<C>>()?.ok_or_else(|| {
                    serde::de::Error::invalid_length(
                        2usize,
                        &"struct PublicKeyPackage with 4 elements",
                    )
                })?;

                // For the `min_signers` field, fill it with None if
                // `next_element()` fails (i.e. there are no other elements)
                let min_signers = match seq.next_element::<Option<u16>>() {
                    Ok(Some(min_signers)) => min_signers,
                    _ => None,
                };

                Ok(PublicKeyPackage {
                    header,
                    verifying_shares,
                    verifying_key,
                    min_signers,
                })
            }

            // Again this is copied from the `serde::Deserialize` derive;
            // the only change is not requiring `min_signers` to be present.
            fn visit_map<__A>(self, mut __map: __A) -> Result<Self::Value, __A::Error>
            where
                __A: serde::de::MapAccess<'de>,
            {
                let mut __field0: Option<Header<C>> = None;
                let mut __field1: Option<BTreeMap<Identifier<C>, VerifyingShare<C>>> = None;
                let mut __field2: Option<VerifyingKey<C>> = None;
                let mut __field3: Option<Option<u16>> = None;
                while let Some(__key) = serde::de::MapAccess::next_key::<Field>(&mut __map)? {
                    match __key {
                        Field::Field0 => {
                            if Option::is_some(&__field0) {
                                return Err(<__A::Error as serde::de::Error>::duplicate_field(
                                    "header",
                                ));
                            }
                            __field0 =
                                Some(serde::de::MapAccess::next_value::<Header<C>>(&mut __map)?);
                        }
                        Field::Field1 => {
                            if Option::is_some(&__field1) {
                                return Err(<__A::Error as serde::de::Error>::duplicate_field(
                                    "verifying_shares",
                                ));
                            }
                            __field1 = Some(serde::de::MapAccess::next_value::<
                                BTreeMap<Identifier<C>, VerifyingShare<C>>,
                            >(&mut __map)?);
                        }
                        Field::Field2 => {
                            if Option::is_some(&__field2) {
                                return Err(<__A::Error as serde::de::Error>::duplicate_field(
                                    "verifying_key",
                                ));
                            }
                            __field2 = Some(serde::de::MapAccess::next_value::<VerifyingKey<C>>(
                                &mut __map,
                            )?);
                        }
                        Field::Field3 => {
                            if Option::is_some(&__field3) {
                                return Err(<__A::Error as serde::de::Error>::duplicate_field(
                                    "min_signers",
                                ));
                            }
                            __field3 =
                                Some(serde::de::MapAccess::next_value::<Option<u16>>(&mut __map)?);
                        }
                    }
                }
                let __field0 = match __field0 {
                    Some(__field0) => __field0,
                    None => Err(<__A::Error as serde::de::Error>::missing_field("header"))?,
                };
                let __field1 = match __field1 {
                    Some(__field1) => __field1,
                    None => Err(<__A::Error as serde::de::Error>::missing_field(
                        "verifying_shares",
                    ))?,
                };
                let __field2 = match __field2 {
                    Some(__field2) => __field2,
                    None => Err(<__A::Error as serde::de::Error>::missing_field(
                        "verifying_key",
                    ))?,
                };
                let __field3 = __field3.unwrap_or_default();
                Ok(PublicKeyPackage {
                    header: __field0,
                    verifying_shares: __field1,
                    verifying_key: __field2,
                    min_signers: __field3,
                })
            }
        }

        const FIELDS: &[&str] = &["header", "verifying_shares", "verifying_key", "min_signers"];
        deserializer.deserialize_struct(
            "PublicKeyPackage",
            FIELDS,
            Visitor {
                marker: PhantomData::<C>,
            },
        )
    }
}
