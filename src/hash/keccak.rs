//! A wrapper around the Keccak-f\[1600\] permutation.
//!
//! **Warning**: this function is not SHA3.
//! Despite internally we use the same permutation,
//! we build a duplex sponge in overwrite mode
//! on the top of it using the `DuplexSponge` trait.
use core::ops::{Index, IndexMut, Range, RangeFrom, RangeTo};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::sponge::{DuplexSponge, Sponge};

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
        state[..32].copy_from_slice(&tag);
        state
    }

    fn permute(&mut self) {
        // self.state[self.pos as usize] ^= self.pos_begin;
        // self.state[(self.pos + 1) as usize] ^= 0x04;
        // self.state[(RATE + 1) as usize] ^= 0x80;
        keccak::f1600(transmute_state(self));
    }
}

impl Default for AlignedKeccakState {
    fn default() -> Self {
        Self([0u8; Self::CAPACITY + Self::RATE])
    }
}

impl Index<usize> for AlignedKeccakState {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for AlignedKeccakState {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl Index<Range<usize>> for AlignedKeccakState {
    type Output = [u8];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<Range<usize>> for AlignedKeccakState {
    fn index_mut(&mut self, index: Range<usize>) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl Index<RangeFrom<usize>> for AlignedKeccakState {
    type Output = [u8];

    fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<RangeFrom<usize>> for AlignedKeccakState {
    fn index_mut(&mut self, index: RangeFrom<usize>) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl Index<RangeTo<usize>> for AlignedKeccakState {
    type Output = [u8];

    fn index(&self, index: RangeTo<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<RangeTo<usize>> for AlignedKeccakState {
    fn index_mut(&mut self, index: RangeTo<usize>) -> &mut Self::Output {
        &mut self.0[index]
    }
}
