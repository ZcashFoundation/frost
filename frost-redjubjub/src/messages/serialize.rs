//! Serialization rules specified in [RFC-001#Serialize-Deserialize]
//!
//! We automatically serialize and deserialize using serde derivations where possible.
//! Sometimes we need to implement ourselves, this file holds that code.
//!
//! [RFC-001#Serialize-Deserialize]: https://github.com/ZcashFoundation/redjubjub/blob/main/rfcs/0001-messages.md#serializationdeserialization

use serde::ser::{Serialize, Serializer};

use serde::de::{self, Deserialize, Deserializer, Visitor};

use super::constants::{
    AGGREGATOR_PARTICIPANT_ID, DEALER_PARTICIPANT_ID, MAX_SIGNER_PARTICIPANT_ID,
};
use super::*;

use std::fmt;

impl Serialize for ParticipantId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            ParticipantId::Signer(id) => {
                assert!(id <= MAX_SIGNER_PARTICIPANT_ID);
                serializer.serialize_u64(id)
            }
            ParticipantId::Dealer => serializer.serialize_u64(DEALER_PARTICIPANT_ID),
            ParticipantId::Aggregator => serializer.serialize_u64(AGGREGATOR_PARTICIPANT_ID),
        }
    }
}

struct ParticipantIdVisitor;

impl<'de> Visitor<'de> for ParticipantIdVisitor {
    type Value = ParticipantId;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(
            format!("an integer between {} and {}", std::u64::MIN, std::u64::MAX).as_str(),
        )
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // Note: deserialization can't fail, because all values are valid.
        if value == DEALER_PARTICIPANT_ID {
            return Ok(ParticipantId::Dealer);
        } else if value == AGGREGATOR_PARTICIPANT_ID {
            return Ok(ParticipantId::Aggregator);
        } else {
            return Ok(ParticipantId::Signer(value));
        }
    }
}

impl<'de> Deserialize<'de> for ParticipantId {
    fn deserialize<D>(deserializer: D) -> Result<ParticipantId, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u64(ParticipantIdVisitor)
    }
}
