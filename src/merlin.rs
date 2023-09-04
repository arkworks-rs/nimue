use super::hash::DuplexHash;
use crate::DefaultHash;

use super::{IOPattern, InvalidTag, Safe};
use core::borrow::Borrow;

/// Merlin is wrapper around a sponge that provides a secure
/// Fiat-Shamir implementation for public-coin protocols.
#[derive(Clone)]
pub struct Merlin<H = DefaultHash>
where
    H: DuplexHash,
{
    safe: Safe<H>,
}

impl<H: DuplexHash> Merlin<H> {
    /// Creates a new [`Merlin`] instance with the given sponge and IO Pattern.
    ///
    /// The resulting object will act as the verifier in a zero-knowledge protocol.
    pub fn new(io_pattern: &IOPattern) -> Self {
        let safe = Safe::new(io_pattern);
        Self { safe }
    }

    /// Absorb a slice of lanes into the sponge.
    #[inline(always)]
    pub fn absorb_native(&mut self, input: &[H::U]) -> Result<(), InvalidTag> {
        self.safe.absorb(input)
    }

    /// Signals the end of the statement.
    #[inline(always)]
    pub fn ratchet(&mut self) -> Result<(), InvalidTag> {
        self.safe.ratchet()
    }

    /// Signals the end of the statement and returns the (compressed) sponge state.
    pub fn ratchet_and_store(self) -> Result<Vec<H::U>, InvalidTag> {
        self.safe.ratchet_and_store()
    }

    /// Get a challenge of `count` elements.
    pub fn squeeze_native(&mut self, dest: &mut [H::U]) -> Result<(), InvalidTag> {
        self.safe.squeeze(dest)
    }
}

impl<H: DuplexHash, B: Borrow<IOPattern>> From<B> for Merlin<H> {
    fn from(io_pattern: B) -> Self {
        Merlin::new(io_pattern.borrow())
    }
}

impl<H: DuplexHash> core::fmt::Debug for Merlin<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Merlin").field(&self.safe).finish()
    }
}
