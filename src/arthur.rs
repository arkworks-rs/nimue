use core::borrow::Borrow;

use rand::{CryptoRng, RngCore};

use super::keccak::Keccak;
use super::{DefaultRng, Duplexer, IOPattern, InvalidTag, Merlin};

// Arthur is a cryptographically-secure random number generator that is
// seeded by a random-number generator and is bound to the protocol transcript.
pub(crate) struct Arthur<R: RngCore + CryptoRng> {
    pub(crate) sponge: Keccak,
    pub(crate) csrng: R,
}

impl<R: RngCore + CryptoRng> RngCore for Arthur<R> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(buf.as_mut());
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(buf.as_mut());
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.csrng.fill_bytes(dest);
        self.sponge.absorb_unchecked(dest);
        self.sponge.squeeze_unchecked(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.sponge.squeeze_unchecked(dest);
        Ok(())
    }
}

/// Builder for the prover state.
pub struct TranscriptBuilder<S: Duplexer>
where
    S: Duplexer,
{
    merlin: Merlin<S>,
    u8sponge: Keccak,
}

impl<S: Duplexer> TranscriptBuilder<S> {
    pub(crate) fn new(io_pattern: &IOPattern) -> Self {
        let merlin = Merlin::new(io_pattern);

        let mut u8sponge = Keccak::new();
        u8sponge.absorb_unchecked(io_pattern.as_bytes());

        Self { u8sponge, merlin }
    }

    // rekey the private sponge with some additional secrets (i.e. with the witness)
    // and divide
    pub fn rekey(mut self, data: &[u8]) -> Self {
        self.u8sponge.absorb_unchecked(data);
        self.u8sponge.divide_unchecked();
        self
    }

    // Finalize the state integrating a cryptographically-secure
    // random number generator that will be used to seed the state before future squeezes.
    pub fn finalize_with_rng<R: RngCore + CryptoRng>(self, csrng: R) -> Transcript<S, R> {
        let arthur = Arthur {
            sponge: self.u8sponge,
            csrng,
        };

        Transcript {
            merlin: self.merlin,
            arthur,
        }
    }
}

impl<S: Duplexer, B: Borrow<IOPattern>> From<B> for Transcript<S> {
    fn from(pattern: B) -> Self {
        TranscriptBuilder::new(pattern.borrow()).finalize_with_rng(DefaultRng::default())
    }
}

/// The state of an interactive proof system.
/// Holds the state of the verifier, and provides the random coins for the prover.
pub struct Transcript<S, R = DefaultRng>
where
    S: Duplexer,
    R: RngCore + CryptoRng,
{
    /// The randomness state of the prover.
    pub(crate) arthur: Arthur<R>,
    pub(crate) merlin: Merlin<S>,
}

impl<S: Duplexer, R: RngCore + CryptoRng> Transcript<S, R> {
    #[inline]
    pub fn append(&mut self, input: &[S::L]) -> Result<&mut Self, InvalidTag> {
        self.merlin.append(input)?;
        Ok(self)
    }

    /// Get a challenge of `count` bytes.
    pub fn challenge_bytes(&mut self, dest: &mut [u8]) -> Result<(), InvalidTag> {
        self.merlin.challenge_bytes(dest)?;
        self.arthur.sponge.absorb_unchecked(dest);
        Ok(())
    }

    #[inline]
    pub fn process(&mut self) -> Result<&mut Self, InvalidTag> {
        self.merlin.process()?;
        Ok(self)
    }

    #[inline]
    pub fn rng<'a>(&'a mut self) -> &'a mut (impl CryptoRng + RngCore) {
        &mut self.arthur
    }
}

impl<R: RngCore + CryptoRng> CryptoRng for Arthur<R> {}

impl<S: Duplexer, R: RngCore + CryptoRng> ::core::fmt::Debug for Transcript<S, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.merlin.fmt(f)
    }
}
