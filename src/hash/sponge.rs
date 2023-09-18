use super::{DuplexHash, Unit};

use core::ops::{Index, IndexMut, Range};
use std::ops::{RangeFrom, RangeTo};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The basic state of a cryptographic sponge.
///
/// A cryptographic sponge operates over some domain `SpongeConfig::U` units.
/// It has a capacity `CAPACITY` and a rate `RATE`,
/// and it permutes its internal state using `SpongeConfig::permute()`.
///
/// For implementors:
///
/// - we write the state in *the first* `Self::RATE` bytes of the state.
/// The last [`Self::CAPACITY`] bytes are never touched directly.
/// - the duplex sponge is in *overwrite mode*.
/// This mode is not known to affect the security levels and removes assumptions on [`Self::U`]
/// as well as constraints in the final zero-knowledge proof implementing the hash function.
pub trait Sponge:
    Zeroize
    + Default
    + Clone
    + Index<usize, Output = Self::U>
    + Index<RangeFrom<usize>, Output = [Self::U]>
    + Index<RangeTo<usize>, Output = [Self::U]>
    + Index<Range<usize>, Output = [Self::U]>
    + IndexMut<RangeFrom<usize>, Output = [Self::U]>
    + IndexMut<RangeTo<usize>, Output = [Self::U]>
    + IndexMut<Range<usize>, Output = [Self::U]>
{
    type U: Unit;
    const CAPACITY: usize;
    const RATE: usize;

    fn new(tag: [u8; 32]) -> Self;
    fn permute(&mut self);
}

/// A cryptographic sponge.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct DuplexSponge<C: Sponge> {
    state: C,
    absorb_pos: usize,
    squeeze_pos: usize,
}

impl<U: Unit, C: Sponge<U = U>> DuplexHash<U> for DuplexSponge<C> {
    fn new(tag: [u8; 32]) -> Self {
        Self {
            state: C::new(tag),
            absorb_pos: 0,
            squeeze_pos: 0,
        }
    }

    fn absorb_unchecked(&mut self, input: &[U]) -> &mut Self {
        if input.is_empty() {
            self.squeeze_pos = C::RATE;
            self
        } else if self.absorb_pos == C::RATE {
            self.state.permute();
            self.absorb_pos = 0;
            self.absorb_unchecked(input)
        } else {
            assert!(!input.is_empty() && self.absorb_pos < C::RATE);
            let chunk_len = usize::min(input.len(), C::RATE - self.absorb_pos);
            let (input, rest) = input.split_at(chunk_len);

            self.state[self.absorb_pos..self.absorb_pos + chunk_len].clone_from_slice(input);
            self.absorb_pos += chunk_len;
            self.absorb_unchecked(rest)
        }
    }

    fn squeeze_unchecked(&mut self, output: &mut [U]) -> &mut Self {
        if output.is_empty() {
            return self;
        }

        if self.squeeze_pos == C::RATE {
            self.squeeze_pos = 0;
            self.absorb_pos = 0;
            self.state.permute();
        }

        assert!(self.squeeze_pos < C::RATE && !output.is_empty());
        let chunk_len = usize::min(output.len(), C::RATE - self.squeeze_pos);
        let (output, rest) = output.split_at_mut(chunk_len);
        output.clone_from_slice(&self.state[self.squeeze_pos..self.squeeze_pos + chunk_len]);
        self.squeeze_pos += chunk_len;
        self.squeeze_unchecked(rest)
    }

    // fn tag(self) -> &'static [Self::U] {
    //     &self.state[C::RATE..]
    // }

    fn ratchet_unchecked(&mut self) -> &mut Self {
        self.state.permute();
        // set to zero the state up to rate
        // XXX. is the compiler really going to do this?
        self.state[0..C::RATE].iter_mut().for_each(|x| x.zeroize());
        self.squeeze_pos = C::RATE;
        self
    }
}
