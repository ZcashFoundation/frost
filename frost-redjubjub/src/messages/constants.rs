//! Definitions of constants.

use super::MsgVersion;

/// The first version of FROST messages
pub const BASIC_FROST_SERIALIZATION: MsgVersion = MsgVersion(0);

/// The fixed participant ID for the dealer.
pub const DEALER_PARTICIPANT_ID: u64 = u64::MAX - 1;

/// The fixed participant ID for the aggregator.
pub const AGGREGATOR_PARTICIPANT_ID: u64 = u64::MAX;

/// The maximum `ParticipantId::Signer` in this serialization format.
///
/// We reserve two participant IDs for the dealer and aggregator.
pub const MAX_SIGNER_PARTICIPANT_ID: u64 = u64::MAX - 2;

/// The maximum number of signers
///
/// By protocol the number of signers can'e be more than 255.
pub const MAX_SIGNERS: u8 = 255;

/// The maximum length of a Zcash message, in bytes.
pub const ZCASH_MAX_PROTOCOL_MESSAGE_LEN: usize = 2 * 1024 * 1024;

/// The minimum number of signers of any FROST setup.
pub const MIN_SIGNERS: usize = 2;

/// The minimum number of signers that must sign.
pub const MIN_THRESHOLD: usize = 2;
