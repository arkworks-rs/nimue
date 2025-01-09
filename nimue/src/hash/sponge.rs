use super::{DuplexHash, Unit};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// The basic state of a cryptographic sponge.
///
/// A cryptographic sponge operates over some domain [`Sponge::U`] units.
/// It has a width [`Sponge::N`] and can process elements at rate [`Sponge::R`],
/// using the permutation function [`Sponge::permute`].
///
/// For implementors:
///
/// - State is written in *the first* [`Sponge::R`] (rate) bytes of the state.
/// The last [`Sponge::N`]-[`Sponge::R`] bytes are never touched directly except during initialization.
/// - The duplex sponge is in *overwrite mode*.
/// This mode is not known to affect the security levels and removes assumptions on [`Sponge::U`]
/// as well as constraints in the final zero-knowledge proof implementing the hash function.
/// - The [`std::default::Default`] implementation *MUST* initialize the state to zero.
/// - The [`Sponge::new`] method should initialize the sponge writing the entropy provided in the `iv` in the last
///     [`Sponge::N`]-[`Sponge::R`] elements of the state.
pub trait Sponge: Zeroize + Default + Clone + AsRef<[Self::U]> + AsMut<[Self::U]> {
    /// The basic unit over which the sponge operates.
    type U: Unit;

    /// The width of the sponge, equal to rate [`Sponge::R`] plus capacity.
    /// Cannot be less than 1. Cannot be less than [`Sponge::R`].
    const N: usize;

    /// The rate of the sponge.
    const R: usize;

    /// Initialize the state of the sponge using 32 bytes of seed.
    fn new(iv: [u8; 32]) -> Self;

    /// Permute the state of the sponge.
    fn permute(&mut self);
}

/// A cryptographic sponge.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct DuplexSponge<C: Sponge> {
    sponge: C,
    absorb_pos: usize,
    squeeze_pos: usize,
}

impl<U: Unit, C: Sponge<U = U>> DuplexHash<U> for DuplexSponge<C> {
    fn new(iv: [u8; 32]) -> Self {
        assert!(C::N > C::R, "Capacity of the sponge should be > 0.");
        Self {
            sponge: C::new(iv),
            absorb_pos: 0,
            squeeze_pos: C::R,
        }
    }

    fn absorb_unchecked(&mut self, mut input: &[U]) -> &mut Self {
        while !input.is_empty() {
            if self.absorb_pos == C::R {
                self.sponge.permute();
                self.absorb_pos = 0;
            } else {
                assert!(!input.is_empty() && self.absorb_pos < C::R);
                let chunk_len = usize::min(input.len(), C::R - self.absorb_pos);
                let (chunk, rest) = input.split_at(chunk_len);

                self.sponge.as_mut()[self.absorb_pos..self.absorb_pos + chunk_len]
                    .clone_from_slice(chunk);
                self.absorb_pos += chunk_len;
                input = rest;
            }
        }
        self.squeeze_pos = C::R;
        self
    }

    fn squeeze_unchecked(&mut self, output: &mut [U]) -> &mut Self {
        if output.is_empty() {
            return self;
        }

        if self.squeeze_pos == C::R {
            self.squeeze_pos = 0;
            self.absorb_pos = 0;
            self.sponge.permute();
        }

        assert!(self.squeeze_pos < C::R && !output.is_empty());
        let chunk_len = usize::min(output.len(), C::R - self.squeeze_pos);
        let (output, rest) = output.split_at_mut(chunk_len);
        output.clone_from_slice(
            &self.sponge.as_ref()[self.squeeze_pos..self.squeeze_pos + chunk_len],
        );
        self.squeeze_pos += chunk_len;
        self.squeeze_unchecked(rest)
    }

    // fn tag(self) -> &'static [Self::U] {
    //     &self.state[C::RATE..]
    // }

    fn ratchet_unchecked(&mut self) -> &mut Self {
        self.sponge.permute();
        // set to zero the state up to rate
        // XXX. is the compiler really going to do this?
        self.sponge.as_mut()[0..C::R]
            .iter_mut()
            .for_each(|x| x.zeroize());
        self.squeeze_pos = C::R;
        self
    }
}
