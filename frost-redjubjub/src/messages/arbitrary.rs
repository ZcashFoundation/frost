use proptest::{
    arbitrary::{any, Arbitrary},
    prelude::*,
};

use super::*;

impl Arbitrary for Header {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<MsgVersion>(),
            any::<ParticipantId>(),
            any::<ParticipantId>(),
        )
            .prop_filter(
                "Sender and receiver participant IDs can not be the same",
                |(_, sender, receiver)| sender != receiver,
            )
            .prop_map(|(version, sender, receiver)| Header {
                version: version,
                sender: sender,
                receiver: receiver,
            })
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for MsgVersion {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        Just(constants::BASIC_FROST_SERIALIZATION).boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

impl Arbitrary for ParticipantId {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            (u64::MIN..=constants::MAX_SIGNER_PARTICIPANT_ID).prop_map(ParticipantId::Signer),
            Just(ParticipantId::Dealer),
            Just(ParticipantId::Aggregator),
        ]
        .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}
