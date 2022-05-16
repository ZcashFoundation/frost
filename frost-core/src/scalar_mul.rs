use std::{
    borrow::Borrow,
    fmt::{Debug, Result},
};

pub trait NonAdjacentForm {
    fn non_adjacent_form(&self, w: usize) -> [i8; 256];
}

impl<C> NonAdjacentForm for Scalar<C>
where
    C: Ciphersuite,
{
    /// Computes a width-\\(w\\) "Non-Adjacent Form" of this scalar.
    ///
    /// Thanks to curve25519-dalek for the original implementation that informed this one.
    ///
    /// The full scalar field MUST fit in 256 bits in this implementation.
    fn non_adjacent_form(&self, w: usize) -> [i8; 256] {
        // required by the NAF definition
        debug_assert!(w >= 2);
        // required so that the NAF digits fit in i8
        debug_assert!(w <= 8);

        use byteorder::{ByteOrder, LittleEndian};

        // NB: Assumes a scalar that fits in 256 bits.
        let mut naf = [0i8; 256];

        let mut x_u64 = [0u64; 5];
        LittleEndian::read_u64_into(&self.to_bytes(), &mut x_u64[0..4]);

        let width = 1 << w;
        let window_mask = width - 1;

        let mut pos = 0;
        let mut carry = 0;
        while pos < 256 {
            // Construct a buffer of bits of the scalar, starting at bit `pos`
            let u64_idx = pos / 64;
            let bit_idx = pos % 64;
            let bit_buf: u64;
            if bit_idx < 64 - w {
                // This window's bits are contained in a single u64
                bit_buf = x_u64[u64_idx] >> bit_idx;
            } else {
                // Combine the current u64's bits with the bits from the next u64
                bit_buf = (x_u64[u64_idx] >> bit_idx) | (x_u64[1 + u64_idx] << (64 - bit_idx));
            }

            // Add the carry into the current window
            let window = carry + (bit_buf & window_mask);

            if window & 1 == 0 {
                // If the window value is even, preserve the carry and continue.
                // Why is the carry preserved?
                // If carry == 0 and window & 1 == 0, then the next carry should be 0
                // If carry == 1 and window & 1 == 0, then bit_buf & 1 == 1 so the next carry should be 1
                pos += 1;
                continue;
            }

            if window < width / 2 {
                carry = 0;
                naf[pos] = window as i8;
            } else {
                carry = 1;
                naf[pos] = (window as i8).wrapping_sub(width as i8);
            }

            pos += w;
        }

        naf
    }
}

/// A trait for variable-time multiscalar multiplication without precomputation.
///
/// Implement for a group element.
pub trait VartimeMultiscalarMul: Clone {
    /// Given an iterator of public scalars and an iterator of
    /// `Option`s of group elements, compute either `Some(Q)`, where
    /// $$
    /// Q = c\_1 E\_1 + \cdots + c\_n E\_n,
    /// $$
    /// if all points were `Some(E_i)`, or else return `None`.
    fn optional_multiscalar_mul<I, J>(scalars: I, elements: J) -> Option<Self>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<Self>>;

    /// Given an iterator of public scalars and an iterator of
    /// public group elements, compute
    /// $$
    /// Q = c\_1 E\_1 + \cdots + c\_n E\_n,
    /// $$
    /// using variable-time operations.
    ///
    /// It is an error to call this function with two iterators of different lengths.
    fn vartime_multiscalar_mul<I, J>(scalars: I, elements: J) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<Self>,
    {
        Self::optional_multiscalar_mul(
            scalars,
            elements.into_iter().map(|e| Some(e.borrow().clone())),
        )
        .unwrap()
    }
}

impl<C> VartimeMultiscalarMul for Element<C>
where
    C: Ciphersuite,
{
    fn optional_multiscalar_mul<I, J>(scalars: I, elements: J) -> Option<Element<C>>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<Element<C>>>,
    {
        let nafs: Vec<_> = scalars
            .into_iter()
            .map(|c| c.borrow().non_adjacent_form(5))
            .collect();

        let lookup_tables = elements
            .into_iter()
            .map(|P_opt| P_opt.map(|P| LookupTable5::<Element<C>>::from(&P)))
            .collect::<Option<Vec<_>>>()?;

        let mut r = <C::Group as Group>::identity();

        for i in (0..256).rev() {
            let mut t = r + r.clone();

            for (naf, lookup_table) in nafs.iter().zip(lookup_tables.iter()) {
                if naf[i] > 0 {
                    t = &t + &lookup_table.select(naf[i] as usize);
                } else if naf[i] < 0 {
                    t = &t - &lookup_table.select(-naf[i] as usize);
                }
            }

            r = t;
        }

        Some(r)
    }
}

/// Holds odd multiples 1A, 3A, ..., 15A of a point A.
#[derive(Copy, Clone)]
pub(crate) struct LookupTable5<T>(pub(crate) [T; 8]);

impl<T: Copy> LookupTable5<T> {
    /// Given public, odd \\( x \\) with \\( 0 < x < 2^4 \\), return \\(xA\\).
    pub fn select(&self, x: usize) -> T {
        debug_assert_eq!(x & 1, 1);
        debug_assert!(x < 16);

        self.0[x / 2]
    }
}

impl<T: Debug> Debug for LookupTable5<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result {
        write!(f, "LookupTable5({:?})", self.0)
    }
}

impl<'a, C> From<&'a <C::Group·as·Group>::Element> for LookupTable5<<C::Group·as·Group>::Element>
where
    C: Ciphersuite,
{
    fn from(A: &'a <C::Group·as·Group>::Element) -> Self {
        let mut Ai = [A; 8];
        let A2 = A * A.clone();
        for i in 0..7 {
            Ai[i + 1] = (&A2 + &Ai[i]);
        }
        // Now Ai = [A, 3A, 5A, 7A, 9A, 11A, 13A, 15A]
        LookupTable5(Ai)
    }
}
