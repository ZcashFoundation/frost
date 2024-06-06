use plonky2::{
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::config::Hasher,
};
use plonky2_field::{
    goldilocks_field::GoldilocksField,
    types::{Field, PrimeField64},
};

/// Poseidon Hash function with 256-bit output
pub fn poseidon_hash(input: &[u8]) -> [u8; 32] {
    let f_input = u8_to_f(input);
    let hashout = PoseidonHash::hash_no_pad(f_input.as_slice());
    hashout_to_u8(&hashout).try_into().unwrap()
}

/// data in big endian, its length should be multiple of 8
pub fn u8_to_f(data: &[u8]) -> Vec<GoldilocksField> {
    data.chunks_exact(8)
        .map(|chunk| {
            GoldilocksField::from_canonical_u64(u64::from_be_bytes(chunk.try_into().unwrap()))
        })
        .collect::<Vec<GoldilocksField>>()
}

pub fn hashout_to_u8(hashout: &HashOut<GoldilocksField>) -> Vec<u8> {
    hashout
        .elements
        .iter()
        .map(|x| x.to_canonical_u64().to_be_bytes())
        .flatten()
        .collect::<Vec<_>>()
}
