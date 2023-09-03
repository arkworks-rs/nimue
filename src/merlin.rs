use crate::DefaultHash;

use super::{Duplexer, IOPattern, InvalidTag, Safe};
use core::borrow::Borrow;

/// Merlin is wrapper around a sponge that provides a secure
/// Fiat-Shamir implementation for public-coin protocols.
#[derive(Clone)]
pub struct Merlin<H = DefaultHash>
where
    H: Duplexer
{
    safe: Safe<H>,
}

impl<H: Duplexer> Merlin<H> {
    /// Creates a new [`Merlin`] instance with the given sponge and IO Pattern.
    ///
    /// The resulting object will act as the verifier in a zero-knowledge protocol.
    pub fn new(io_pattern: &IOPattern) -> Self {
        let safe = Safe::new(io_pattern);
        Self { safe }
    }

    /// Absorb a slice of lanes into the sponge.
    pub fn absorb_native(&mut self, input: &[H::L]) -> Result<&mut Self, InvalidTag> {
        self.safe.absorb(input)?;
        Ok(self)
    }

    /// Signals the end of the statement.
    pub fn ratchet(&mut self) -> Result<&mut Self, InvalidTag> {
        self.safe.divide()?;
        Ok(self)
    }

    /// Signals the end of the statement and returns the (compressed) sponge state.
    pub fn ratchet_and_store(self) -> Result<Vec<H::L>, InvalidTag> {
        self.safe.ratchet_and_store()
    }

    /// Get a challenge of `count` bytes.
    pub fn squeeze_bytes(&mut self, dest: &mut [u8]) -> Result<(), InvalidTag> {
        self.safe.squeeze_bytes(dest)
    }

    // XXX. squeezing native elements is not (yet) supported.
}

impl<H: Duplexer, B: Borrow<IOPattern>> From<B> for Merlin<H> {
    fn from(io_pattern: B) -> Self {
        Merlin::new(io_pattern.borrow())
    }
}

impl<H: Duplexer> core::fmt::Debug for Merlin<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Merlin").field(&self.safe).finish()
    }
}
