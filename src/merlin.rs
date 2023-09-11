use super::hash::DuplexHash;
use crate::DefaultHash;

use crate::errors::InvalidTag;
use crate::hash::Unit;
use crate::safe::{IOPattern, Safe};

/// Merlin is wrapper around a sponge that provides a secure
/// Fiat-Shamir implementation for public-coin protocols.
#[derive(Clone)]
pub struct Merlin<'a, H = DefaultHash, U = u8>
where
    H: DuplexHash<U = U>,
    U: Unit,
{
    safe: Safe<H>,
    transcript: &'a [u8],
}

impl<'a, U: Unit, H: DuplexHash<U = U>> Merlin<'a, H, U> {
    /// Creates a new [`Merlin`] instance with the given sponge and IO Pattern.
    ///
    /// The resulting object will act as the verifier in a zero-knowledge protocol.
    pub fn new(io_pattern: &IOPattern<H>, transcript: &'a [u8]) -> Self {
        let safe = Safe::new(io_pattern);
        Self { safe, transcript }
    }

    /// Read `input.len()` elements from the transcript.
    #[inline(always)]
    pub fn absorb(&mut self, input: &mut [H::U]) -> Result<(), InvalidTag> {
        H::U::read(&mut self.transcript, input).unwrap();
        self.safe.absorb(input)
    }

    #[inline(always)]
    pub fn absorb_common(&mut self, input: &[H::U]) -> Result<(), InvalidTag> {
        self.safe.absorb(input)
    }

    /// Get a challenge of `count` elements.
    #[inline(always)]
    pub fn squeeze(&mut self, input: &mut [H::U]) -> Result<(), InvalidTag> {
        self.safe.squeeze(input)
    }

    /// Signals the end of the statement.
    #[inline(always)]
    pub fn ratchet(&mut self) -> Result<(), InvalidTag> {
        self.safe.ratchet()
    }

    /// Signals the end of the statement and returns the (compressed) sponge state.
    #[inline(always)]
    pub fn preprocess(self) -> Result<&'static [H::U], InvalidTag> {
        self.safe.preprocess()
    }
}

impl<'a, H: DuplexHash<U = U>, U: Unit> core::fmt::Debug for Merlin<'a, H, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Merlin").field(&self.safe).finish()
    }
}

impl<'a, H: DuplexHash<U = u8>> Merlin<'a, H, u8> {
    #[inline(always)]
    pub fn absorb_bytes(&mut self, input: &mut [u8]) -> Result<(), InvalidTag> {
        self.absorb(input)
    }

    #[inline(always)]
    pub fn squeeze_bytes(&mut self, output: &mut [u8]) -> Result<(), InvalidTag> {
        self.squeeze(output)
    }
}
