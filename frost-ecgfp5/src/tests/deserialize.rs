use rand::thread_rng;

use crate::*;

#[test]
fn check_random_serialize() {
    for _ in 0..50 {
        let scalar =
            <<EcGFp5Poseidon256 as Ciphersuite>::Group as Group>::Field::random(&mut thread_rng());
        let point = scalar * <EcGFp5Poseidon256 as Ciphersuite>::Group::generator();
        println!("scalar: {:?}", scalar);
        println!("point: {:?}", point);
        let encoded = <EcGFp5Poseidon256 as Ciphersuite>::Group::serialize(&point);
        let decoded = <EcGFp5Poseidon256 as Ciphersuite>::Group::deserialize(&encoded);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap(), point);
    }
}

#[test]
#[ignore = "I don't know how to construct a non-canonical encoding"]
fn check_deserialize_non_canonical() {
    let mut encoded_generator = <EcGFp5Poseidon256 as Ciphersuite>::Group::serialize(
        &<EcGFp5Poseidon256 as Ciphersuite>::Group::generator(),
    );

    let r = <EcGFp5Poseidon256 as Ciphersuite>::Group::deserialize(&encoded_generator);
    assert!(r.is_ok());

    // The first byte should be 0x02 or 0x03. Set other value to
    // create a non-canonical encoding.
    encoded_generator[0] = 0xFF;
    let r = <EcGFp5Poseidon256 as Ciphersuite>::Group::deserialize(&encoded_generator);
    assert_eq!(r, Err(GroupError::MalformedElement));

    // Besides the first byte, it is still possible to get non-canonical encodings.
    // This is x = p + 2 which is non-canonical and maps to a valid prime-order point.
    let encoded_point =
        hex::decode("02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc31")
            .unwrap()
            .try_into()
            .unwrap();
    let r = <EcGFp5Poseidon256 as Ciphersuite>::Group::deserialize(&encoded_point);
    assert_eq!(r, Err(GroupError::MalformedElement));
}

#[test]
fn check_deserialize_identity() {
    // The identity is actually encoded as a single byte; but the API does not
    // allow us to change that. Try to send something similar.
    let encoded_identity = [0u8; 40];

    let r = <EcGFp5Poseidon256 as Ciphersuite>::Group::deserialize(&encoded_identity);
    assert_eq!(r, Err(GroupError::InvalidIdentityElement));
}
