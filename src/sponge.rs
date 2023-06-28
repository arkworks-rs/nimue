use super::{Duplexer, Lane};

use core::ops::{Index, IndexMut, Range};
use std::ops::{RangeFrom, RangeTo};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The basic state of a cryptographic sponge.
///
/// A cryptographic sponge operates over some domain `SpongeConfig::L` of lanes.
/// It has a capacity `CAPACITY` and a rate `RATE`,
/// and it permutes its internal state using `SpongeConfig::permute()`.
pub trait Sponge:
    Zeroize
    + Default
    + Clone
    + Index<usize, Output = Self::L>
    + Index<RangeFrom<usize>, Output = [Self::L]>
    + Index<RangeTo<usize>, Output = [Self::L]>
    + Index<Range<usize>, Output = [Self::L]>
    + IndexMut<RangeFrom<usize>, Output = [Self::L]>
    + IndexMut<RangeTo<usize>, Output = [Self::L]>
    + IndexMut<Range<usize>, Output = [Self::L]>
{
    type L: Lane;

    const CAPACITY: usize;
    const RATE: usize;

    fn permute(&mut self);
}

/// A cryptographic sponge.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DuplexSponge<C: Sponge> {
    state: C,
    absorb_pos: usize,
    squeeze_pos: usize,
}

impl<F: Lane, C: Sponge<L = F>> Duplexer for DuplexSponge<C> {
    type L = F;

    fn new() -> Self {
        let mut state = C::default();
        state.permute();
        Self {
            state,
            absorb_pos: 0,
            squeeze_pos: 0,
        }
    }

    fn absorb_unchecked(&mut self, input: &[Self::L]) -> &mut Self {
        if input.len() == 0 {
            self.squeeze_pos = C::RATE;
            self
        } else if self.absorb_pos == C::RATE {
            self.state.permute();
            self.absorb_pos = 0;
            self.absorb_unchecked(input)
        } else {
            assert!(0 < input.len() && self.absorb_pos < C::RATE);
            let chunk_len = usize::min(input.len(), C::RATE - self.absorb_pos);
            let (input, rest) = input.split_at(chunk_len);

            self.state[self.absorb_pos..self.absorb_pos + chunk_len].clone_from_slice(&input);
            self.absorb_pos += chunk_len;
            self.absorb_unchecked(rest)
        }
    }

    fn squeeze_unchecked(&mut self, output: &mut [Self::L]) -> &mut Self {
        if output.len() == 0 {
            return self;
        }

        if self.squeeze_pos == C::RATE {
            self.squeeze_pos = 0;
            self.absorb_pos = 0;
            self.state.permute();
        }

        assert!(self.squeeze_pos < C::RATE && output.len() > 0);
        let chunk_len = usize::min(output.len(), C::RATE - self.squeeze_pos);
        let (output, rest) = output.split_at_mut(chunk_len);
        output.clone_from_slice(&self.state[self.squeeze_pos..self.squeeze_pos + chunk_len]);
        self.squeeze_pos += chunk_len;
        self.squeeze_unchecked(rest)
    }

    fn load_unchecked(input: &[Self::L]) -> Self {
        let len = usize::min(input.len(), C::CAPACITY);
        let mut sponge = Self::new();
        sponge.state[C::RATE..C::RATE + len].clone_from_slice(&input[..len]);
        sponge
    }

    fn store_unchecked(&self) -> &[Self::L] {
        &self.state[C::CAPACITY..]
    }

    fn divide_unchecked(&mut self) -> &mut Self {
        self.state.permute();
        // set to zero the state up to rate
        self.state[0..C::RATE].iter_mut().for_each(|x| x.zeroize());
        self.squeeze_pos = C::RATE;
        self
    }
}
