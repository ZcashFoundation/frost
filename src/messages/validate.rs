//! Validation rules specified in [RFC-001#rules]
//!
//! [RFC-001#rules]: https://github.com/ZcashFoundation/redjubjub/blob/main/rfcs/0001-messages.md#rules

use super::constants::{
    BASIC_FROST_SERIALIZATION, MAX_SIGNERS, MIN_SIGNERS, MIN_THRESHOLD,
    ZCASH_MAX_PROTOCOL_MESSAGE_LEN,
};
use super::*;

use thiserror::Error;

pub trait Validate {
    fn validate(&self) -> Result<&Self, MsgErr>;
}

impl Validate for Message {
    fn validate(&self) -> Result<&Self, MsgErr> {
        match self.payload {
            Payload::SharePackage(_) => {
                if self.header.sender != ParticipantId::Dealer {
                    return Err(MsgErr::SenderMustBeDealer);
                }
                if !matches!(self.header.receiver, ParticipantId::Signer(_)) {
                    return Err(MsgErr::ReceiverMustBeSigner);
                }
            }
            Payload::SigningCommitments(_) => {
                if !matches!(self.header.sender, ParticipantId::Signer(_)) {
                    return Err(MsgErr::SenderMustBeSigner);
                }
                if self.header.receiver != ParticipantId::Aggregator {
                    return Err(MsgErr::ReceiverMustBeAggregator);
                }
            }
            Payload::SigningPackage(_) => {
                if self.header.sender != ParticipantId::Aggregator {
                    return Err(MsgErr::SenderMustBeAggregator);
                }
                if !matches!(self.header.receiver, ParticipantId::Signer(_)) {
                    return Err(MsgErr::ReceiverMustBeSigner);
                }
            }
            Payload::SignatureShare(_) => {
                if !matches!(self.header.sender, ParticipantId::Signer(_)) {
                    return Err(MsgErr::SenderMustBeSigner);
                }
                if self.header.receiver != ParticipantId::Aggregator {
                    return Err(MsgErr::ReceiverMustBeAggregator);
                }
            }
            Payload::AggregateSignature(_) => {
                if self.header.sender != ParticipantId::Aggregator {
                    return Err(MsgErr::SenderMustBeAggregator);
                }
                if !matches!(self.header.receiver, ParticipantId::Signer(_)) {
                    return Err(MsgErr::ReceiverMustBeSigner);
                }
            }
        }
        self.header.validate()?;
        self.payload.validate()?;
        Ok(self)
    }
}

impl Validate for Header {
    fn validate(&self) -> Result<&Self, MsgErr> {
        // Validate the message version.
        // By now we only have 1 valid version so we compare against that.
        if self.version != BASIC_FROST_SERIALIZATION {
            return Err(MsgErr::WrongVersion);
        }

        // Make sure the sender and the receiver are not the same.
        if self.sender == self.receiver {
            return Err(MsgErr::SameSenderAndReceiver);
        }
        Ok(self)
    }
}

impl Validate for Payload {
    fn validate(&self) -> Result<&Self, MsgErr> {
        match self {
            Payload::SharePackage(share_package) => {
                if share_package.share_commitment.len() < MIN_SIGNERS {
                    return Err(MsgErr::NotEnoughCommitments(MIN_SIGNERS));
                }

                if share_package.share_commitment.len() > MAX_SIGNERS.into() {
                    return Err(MsgErr::TooManyCommitments);
                }
            }
            Payload::SigningCommitments(_) => {}
            Payload::SigningPackage(signing_package) => {
                if signing_package.message.len() > ZCASH_MAX_PROTOCOL_MESSAGE_LEN {
                    return Err(MsgErr::MsgTooBig);
                }

                if signing_package.signing_commitments.len() < MIN_THRESHOLD {
                    return Err(MsgErr::NotEnoughCommitments(MIN_THRESHOLD));
                }

                if signing_package.signing_commitments.len() > MAX_SIGNERS.into() {
                    return Err(MsgErr::TooManyCommitments);
                }
            }
            Payload::SignatureShare(_) => {}
            Payload::AggregateSignature(_) => {}
        }

        Ok(self)
    }
}

/// The error a message can produce if it fails validation.
#[derive(Error, Debug, PartialEq)]
pub enum MsgErr {
    #[error("wrong version number")]
    WrongVersion,
    #[error("sender and receiver are the same")]
    SameSenderAndReceiver,
    #[error("the sender of this message must be the dealer")]
    SenderMustBeDealer,
    #[error("the receiver of this message must be a signer")]
    ReceiverMustBeSigner,
    #[error("the sender of this message must be a signer")]
    SenderMustBeSigner,
    #[error("the receiver of this message must be the aggregator")]
    ReceiverMustBeAggregator,
    #[error("the sender of this message must be the aggregator")]
    SenderMustBeAggregator,
    #[error("the number of signers must be at least {0}")]
    NotEnoughCommitments(usize),
    #[error("the number of signers can't be more than {}", MAX_SIGNERS)]
    TooManyCommitments,
    #[error(
        "the message field can't be bigger than {}",
        ZCASH_MAX_PROTOCOL_MESSAGE_LEN
    )]
    MsgTooBig,
}
