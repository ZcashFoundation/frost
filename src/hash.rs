use blake2b_simd::{Params, State};

use crate::Scalar;

/// Provides H^star, the hash-to-scalar function used by RedJubjub.
pub struct HStar {
    state: State,
}

impl Default for HStar {
    fn default() -> Self {
        let state = Params::new()
            .hash_length(64)
            .personal(b"Zcash_RedJubjubH")
            .to_state();
        Self { state }
    }
}

impl HStar {
    /// Add `data` to the hash.
    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// Consume `self` to compute the hash output.
    pub fn finalize(mut self) -> Scalar {
        Scalar::from_bytes_wide(self.state.finalize().as_array())
    }
}
