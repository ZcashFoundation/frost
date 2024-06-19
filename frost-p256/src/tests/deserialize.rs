use crate::*;

#[test]
fn check_deserialize_non_canonical() {
    let mut encoded_generator = <P256Sha256 as Ciphersuite>::Group::serialize(
        &<P256Sha256 as Ciphersuite>::Group::generator(),
    )
    .unwrap();

    let r = <P256Sha256 as Ciphersuite>::Group::deserialize(&encoded_generator);
    assert!(r.is_ok());

    // The first byte should be 0x02 or 0x03. Set other value to
    // create a non-canonical encoding.
    encoded_generator[0] = 0xFF;
    let r = <P256Sha256 as Ciphersuite>::Group::deserialize(&encoded_generator);
    assert_eq!(r, Err(GroupError::MalformedElement));

    // Besides the first byte, it is still possible to get non-canonical encodings.
    // This is x = p + 5 which is non-canonical and maps to a valid prime-order point.
    let encoded_point =
        hex::decode("02ffffffff00000001000000000000000000000001000000000000000000000004")
            .unwrap()
            .try_into()
            .unwrap();
    let r = <P256Sha256 as Ciphersuite>::Group::deserialize(&encoded_point);
    assert_eq!(r, Err(GroupError::MalformedElement));
}

#[test]
fn check_deserialize_identity() {
    // The identity is actually encoded as a single byte; but the API does not
    // allow us to change that. Try to send something similar.
    let encoded_identity = [0u8; 33];

    let r = <P256Sha256 as Ciphersuite>::Group::deserialize(&encoded_identity);
    assert_eq!(r, Err(GroupError::MalformedElement));
}
