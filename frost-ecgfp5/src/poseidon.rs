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
    let f_input = u8_to_goldilocks(input);
    let hashout = PoseidonHash::hash_no_pad(f_input.as_slice());
    hashout_to_u8(&hashout).try_into().unwrap()
}

/// Convert [u8; 4] to one GoldilocksField
/// 
/// Since [u8; 8] -> GoldilocksField is non-canoncial, we need to convert [u8; 4] -> u32 -> GoldilocksField 
pub fn u8_to_goldilocks(data: &[u8]) -> Vec<GoldilocksField> {
    const CHUNK_SIZE: usize = 4;
    data.chunks(CHUNK_SIZE)
        .map(|chunk| {
            let mut padded = [0u8; CHUNK_SIZE];
            let len = chunk.len().min(CHUNK_SIZE);
            padded[..len].copy_from_slice(&chunk[..len]);
            GoldilocksField::from_canonical_u32(u32::from_le_bytes(padded))
        })
        .collect::<Vec<GoldilocksField>>()
}

pub fn hashout_to_u8(hashout: &HashOut<GoldilocksField>) -> Vec<u8> {
    hashout
        .elements
        .iter()
        .map(|x| x.to_canonical_u64().to_le_bytes())
        .flatten()
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use plonky2_field::types::Field64;

    use super::*;

    #[test]
    fn test_u8_to_goldilocks_collision() {
        let one = 1u64.to_le_bytes();
        let order_plus_one = (GoldilocksField::ORDER + 1).to_le_bytes();
        assert_ne!(one, order_plus_one);
        assert_ne!(u8_to_goldilocks(&one), u8_to_goldilocks(&order_plus_one));
    }

    #[test]
    fn test_hash() {
        {
            let msg = b"test message longer than 32 bytes = 4 goldilocks elements";
            let mut invalid_msg = msg.clone().to_vec();
            invalid_msg.push(90);
            let hash1 = poseidon_hash(msg);
            let hash2 = poseidon_hash(&invalid_msg);
            assert_ne!(hash1, hash2);
        }
        {
            let msg = b"test message < 32 bytes";
            let mut invalid_msg = msg.clone().to_vec();
            invalid_msg.push(90);
            let hash1 = poseidon_hash(msg);
            let hash2 = poseidon_hash(&invalid_msg);
            assert_ne!(hash1, hash2);
        }
    }
}
