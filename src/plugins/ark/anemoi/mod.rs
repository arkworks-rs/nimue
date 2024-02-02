//! Work-in-progress (but working) implementation of the Anemoi hash function.
//!
//! The main reason for this code not being deployed is that [anemoi](https://anemoi-hash.github.io/)'s Rust implementation
//! is not published as a crate and thus `nimue` cannot publish it along with a new release.

use ark_ff::Field;
use std::ops::{Index, IndexMut, Range, RangeFrom, RangeTo};
use zeroize::Zeroize;

use super::sponge::Sponge;

#[derive(Clone, Zeroize)]
pub struct AnemoiState<F: Field, const R: usize, const N: usize>([F; N]);

impl<F: Field, const N: usize, const R: usize> Default for AnemoiState<F, R, N> {
    fn default() -> Self {
        Self([F::zero(); N])
    }
}

crate::hash::index::impl_indexing!(AnemoiState, 0, Output = F, Params = [F: Field], Constants = [R, N]);

pub type AnemoiBls12_381_2_1 = AnemoiState<anemoi::bls12_381::Felt, 2, 1>;
use anemoi::bls12_381::anemoi_2_1::AnemoiBls12_381_2_1 as _AnemoiBls12_381_2_1;
use anemoi::Anemoi;

impl Sponge
    for AnemoiState<
        anemoi::bls12_381::Felt,
        { _AnemoiBls12_381_2_1::RATE },
        { _AnemoiBls12_381_2_1::WIDTH },
    >
{
    type U = anemoi::bls12_381::Felt;

    const CAPACITY: usize = _AnemoiBls12_381_2_1::WIDTH - _AnemoiBls12_381_2_1::RATE;

    const RATE: usize = _AnemoiBls12_381_2_1::RATE;

    fn new(iv: [u8; 32]) -> Self {
        let mut state = Self::default();
        state[RATE] = anemoi::bls12_381::Felt::from_le_bytes_mod_order(&iv);
        state
    }

    fn permute(&mut self) {
        _AnemoiBls12_381_2_1::permutation(&mut self.0)
    }
}
