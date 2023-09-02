use crate::DefaultHash;

use super::{Duplexer, IOPattern, InvalidTag, Lane, Safe};
use core::borrow::Borrow;

/// Merlin is wrapper around a sponge that provides a secure
/// Fiat-Shamir implementation for public-coin protocols.
#[derive(Clone)]
pub struct Merlin<H = DefaultHash>
where
    H: Duplexer,
{
    safe: Safe<H>,
    leftovers: Vec<u8>,
}

impl<H: Duplexer> Merlin<H> {
    /// Creates a new [`Merlin`] instance with the given sponge and IO Pattern.
    ///
    /// The resulting object will act as the verifier in a zero-knowledge protocol.
    pub fn new(io_pattern: &IOPattern) -> Self {
        let safe = Safe::new(io_pattern);
        let leftovers = Vec::with_capacity(H::L::extractable_bytelen());
        Self { safe, leftovers }
    }

    /// Absorb a slice of lanes into the sponge.
    pub fn append(&mut self, input: &[H::L]) -> Result<&mut Self, InvalidTag> {
        self.leftovers.clear();
        self.safe.absorb(input)?;
        Ok(self)
    }

    /// Signals the end of the statement.
    pub fn process(&mut self) -> Result<&mut Self, InvalidTag> {
        self.leftovers.clear();
        self.safe.divide()?;
        Ok(self)
    }

    /// Signals the end of the statement and returns the (compressed) sponge state.
    pub fn divide_and_store(self) -> Result<Vec<H::L>, InvalidTag> {
        self.safe.divide_and_store()
    }

    /// Get a challenge of `count` bytes.
    pub fn challenge_bytes(&mut self, dest: &mut [u8]) -> Result<(), InvalidTag> {
        self.safe.squeeze_bytes(dest)
    }

    // pub fn challenge_native(&mut self, mut dest: &mut [S::L]) -> Result<(), InvalidTag> {
    //     self.safe.squeeze(&mut dest)
    // }
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
