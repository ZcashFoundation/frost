use proptest::prelude::*;

use crate::messages::*;

proptest! {
    #[test]
    fn serialize_message(
        message in any::<Message>(),
    ) {
        let serialized = bincode::serialize(&message).unwrap();
        let deserialized: Message = bincode::deserialize(serialized.as_slice()).unwrap();

        prop_assert_eq!(message, deserialized);
    }
}
