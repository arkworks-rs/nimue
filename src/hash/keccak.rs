//! **Warning**: this function is not SHA3.
//! Despite internally we use the same permutation function,
//! we build a duplex sponge in overwrite mode
//! on the top of it using the `DuplexSponge` trait.
use super::sponge::{DuplexSponge, Sponge};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A duplex sponge based on the permutation [`keccak::f1600`]
/// using [`DuplexSponge`].
pub type Keccak = DuplexSponge<AlignedKeccakState>;

fn transmute_state(st: &mut AlignedKeccakState) -> &mut [u64; 25] {
    unsafe { &mut *(st as *mut AlignedKeccakState as *mut [u64; 25]) }
}

/// This is a wrapper around 200-byte buffer that's always 8-byte aligned
/// to make pointers to it safely convertible to pointers to [u64; 25]
/// (since u64 words must be 8-byte aligned)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct AlignedKeccakState([u8; 200]);

impl Sponge for AlignedKeccakState {
    type U = u8;
    const CAPACITY: usize = 64;
    const RATE: usize = 136;

    fn new(tag: [u8; 32]) -> Self {
        let mut state = Self::default();
        state[Self::RATE..Self::RATE + 32].copy_from_slice(&tag);
        state
    }

    fn permute(&mut self) {
        keccak::f1600(transmute_state(self));
    }
}

impl Default for AlignedKeccakState {
    fn default() -> Self {
        Self([0u8; Self::CAPACITY + Self::RATE])
    }
}

super::index::impl_indexing!(
    AlignedKeccakState,
    0,
    Output = u8,
    Params = [],
    Constants = []
);
