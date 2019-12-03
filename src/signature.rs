/// A RedJubJub signature.
pub struct Signature(pub [u8; 64]);

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Signature {
        Signature(bytes)
    }
}

impl From<Signature> for [u8; 64] {
    fn from(s: Signature) -> [u8; 64] {
        s.0
    }
}
