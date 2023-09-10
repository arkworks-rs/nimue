use super::hash::DuplexHash;
use crate::DefaultHash;

use crate::errors::InvalidTag;
use crate::hash::Unit;
use crate::safe::{IOPattern, Safe};

/// Merlin is wrapper around a sponge that provides a secure
/// Fiat-Shamir implementation for public-coin protocols.
#[derive(Clone)]
pub struct Merlin<H = DefaultHash, U = u8>
where
    H: DuplexHash<U = U>,
    U: Unit,
{
    safe: Safe<H>,
    transcript: Vec<u8>
}

impl<U: Unit, H: DuplexHash<U = U>> Merlin<H, U> {
    /// Creates a new [`Merlin`] instance with the given sponge and IO Pattern.
    ///
    /// The resulting object will act as the verifier in a zero-knowledge protocol.
    pub fn new(io_pattern: &IOPattern<H>) -> Self {
        let safe = Safe::new(io_pattern);
        let transcript = Vec::new();
        Self { safe, transcript }
    }

    fn absorb(&mut self, input: &mut [H::U]) -> Result<(), InvalidTag> {
        H::U::read(&mut self.transcript.as_slice(), input).unwrap();
        self.safe.absorb(input)
    }

    fn absorb_common(&mut self, input: &[H::U], ) -> Result<(), InvalidTag> {
        self.safe.absorb(input)
    }

    fn squeeze(&mut self, input: &mut [H::U]) -> Result<(), InvalidTag> {
        self.safe.squeeze(input)
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
    #[inline(always)]
    pub fn ratchet_and_store(self) -> Result<Vec<H::U>, InvalidTag> {
        self.safe.ratchet_and_store()
    }

    /// Get a challenge of `count` elements.
    #[inline(always)]
    pub fn squeeze_native(&mut self, output: &mut [H::U]) -> Result<(), InvalidTag> {
        self.safe.squeeze(output)
    }
}

impl<H: DuplexHash<U = U>, U: Unit> core::fmt::Debug for Merlin<H, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Merlin").field(&self.safe).finish()
    }
}

impl<H: DuplexHash<U = u8>> Merlin<H, u8> {
    #[inline(always)]
    pub fn absorb_bytes(&mut self, input: &[u8]) -> Result<(), InvalidTag> {
        self.absorb_native(input)
    }

    #[inline(always)]
    pub fn squeeze_bytes(&mut self, output: &mut [u8]) -> Result<(), InvalidTag> {
        self.squeeze_native(output)
    }
}
