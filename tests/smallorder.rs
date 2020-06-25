use std::convert::TryFrom;

use jubjub::{AffinePoint, Fq};

use redjubjub::*;

#[test]
fn smallorder_publickey_fails() {
    // (1,0) is a point of order 4 on any Edwards curve
    let order4 = AffinePoint::from_raw_unchecked(Fq::one(), Fq::zero());
    assert_eq!(<bool>::from(order4.is_small_order()), true);
    let bytes = order4.to_bytes();
    let pk_bytes = VerificationKeyBytes::<SpendAuth>::from(bytes);
    assert!(VerificationKey::<SpendAuth>::try_from(pk_bytes).is_err());
}
