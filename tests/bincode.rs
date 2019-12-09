use std::convert::TryFrom;

use proptest::prelude::*;

use redjubjub_zebra::*;

proptest! {
    #[test]
    fn publickeybytes_serialization(
        bytes in prop::array::uniform32(any::<u8>()),
    ) {
        let pk_bytes_from = PublicKeyBytes::<SpendAuth>::from(bytes);
        let pk_bytes_bincode: PublicKeyBytes::<SpendAuth>
            = bincode::deserialize(&bytes[..]).unwrap();

        // Check 1: both decoding methods should have the same result.
        assert_eq!(pk_bytes_from, pk_bytes_bincode);

        // Check 2: bincode encoding should match original bytes.
        let bytes_bincode = bincode::serialize(&pk_bytes_from).unwrap();
        assert_eq!(&bytes[..], &bytes_bincode[..]);

        // Check 3: From encoding should match original bytes.
        let bytes_from: [u8; 32] = pk_bytes_bincode.into();
        assert_eq!(&bytes[..], &bytes_from[..]);
    }

    #[test]
    fn signature_serialization(
        lo in prop::array::uniform32(any::<u8>()),
        hi in prop::array::uniform32(any::<u8>()),
    ) {
        // array length hack
        let bytes = {
            let mut bytes = [0; 64];
            bytes[0..32].copy_from_slice(&lo[..]);
            bytes[32..64].copy_from_slice(&hi[..]);
            bytes
        };

        let sig_bytes_from = Signature::<SpendAuth>::from(bytes);
        let sig_bytes_bincode: Signature::<SpendAuth>
            = bincode::deserialize(&bytes[..]).unwrap();

        // Check 1: both decoding methods should have the same result.
        assert_eq!(sig_bytes_from, sig_bytes_bincode);

        // Check 2: bincode encoding should match original bytes.
        let bytes_bincode = bincode::serialize(&sig_bytes_from).unwrap();
        assert_eq!(&bytes[..], &bytes_bincode[..]);

        // Check 3: From encoding should match original bytes.
        let bytes_from: [u8; 64] = sig_bytes_bincode.into();
        assert_eq!(&bytes[..], &bytes_from[..]);
    }
}
