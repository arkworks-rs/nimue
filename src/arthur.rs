use rand::{CryptoRng, RngCore};

use crate::hash::Unit;
use crate::{ByteWriter, IOPattern, Safe, UnitTranscript};

use super::hash::{DuplexHash, Keccak};
use super::{DefaultHash, DefaultRng, IOPatternError};

/// A cryptographically-secure random number generator that is bound to the protocol transcript.
///
/// For most public-coin protocols it is *vital* not to have two different verifier messages for the same prover message.
/// For this reason, we construct a Rng that will absorb whatever the verifier absorbs, and that in addition
/// it is seeded by a cryptographic random number generator (by default, [`rand::rngs::OsRng`]).
///
/// Every time the prover's sponge is squeeze, the state of the sponge is ratcheted, so that it can't be inverted and the randomness recovered.
pub(crate) struct ProverRng<R: RngCore + CryptoRng> {
    /// The sponge that is used to generate the random coins.
    pub(crate) sponge: Keccak,
    /// The cryptographic random number generator that seeds the sponge.
    pub(crate) csrng: R,
}

impl<R: RngCore + CryptoRng> RngCore for ProverRng<R> {
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
        // Seed (at most) 32 bytes of randomness from the CSRNG
        let len = usize::min(dest.len(), 32);
        self.csrng.fill_bytes(&mut dest[..len]);
        self.sponge.absorb_unchecked(&dest[..len]);
        // fill `dest` with the output of the sponge
        self.sponge.squeeze_unchecked(dest);
        // erase the state from the sponge so that it can't be reverted
        self.sponge.ratchet_unchecked();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.sponge.squeeze_unchecked(dest);
        Ok(())
    }
}

impl<H, U, R> Arthur<H, U, R>
where
    H: DuplexHash<U>,
    R: RngCore + CryptoRng,
    U: Unit,
{
    pub fn new(io_pattern: &IOPattern<H, U>, csrng: R) -> Self {
        let safe = Safe::new(io_pattern);

        let mut sponge = Keccak::default();
        sponge.absorb_unchecked(io_pattern.as_bytes());
        let rng = ProverRng { sponge, csrng };

        Self {
            rng,
            safe,
            transcript: Vec::new(),
        }
    }
}

impl<U, H, D> From<D> for Arthur<H, U, DefaultRng>
where
    U: Unit,
    H: DuplexHash<U>,
    D: core::ops::Deref<Target = IOPattern<H, U>>,
{
    fn from(pattern: D) -> Self {
        Arthur::new(pattern.deref(), DefaultRng::default())
    }
}

/// [`Arthur`] is the prover state in an interactive proof system.
/// It internally holds the secret coins of the prover for zero-knowledge, and
/// has the hash function state for the verifier state.
///
/// Unless otherwise specified,
/// [`Arthur`] is set to work over bytes with [`DefaultHash`] and
/// rely on the default random number generator [`DefaultRng`].
pub struct Arthur<H = DefaultHash, U = u8, R = DefaultRng>
where
    U: Unit,
    H: DuplexHash<U>,
    R: RngCore + CryptoRng,
{
    /// The randomness state of the prover.
    pub(crate) rng: ProverRng<R>,
    /// The public coins for the protocol
    pub(crate) safe: Safe<H, U>,
    /// The encoded data.
    pub(crate) transcript: Vec<u8>,
}

impl<H, U, R> Arthur<H, U, R>
where
    U: Unit,
    H: DuplexHash<U>,
    R: RngCore + CryptoRng,
{
    /// Add a slice `[Arthur::U]` to the protocol transcript.
    /// The messages are also internally encoded in the protocol transcript,
    /// and used to re-seed the prover's random number generator.
    #[inline(always)]
    pub fn add_units(&mut self, input: &[U]) -> Result<(), IOPatternError> {
        // let serialized = bincode::serialize(input).unwrap();
        // self.arthur.sponge.absorb_unchecked(&serialized);
        let old_len = self.transcript.len();
        // write never fails on Vec<u8>
        U::write(input, &mut self.transcript).unwrap();
        self.rng
            .sponge
            .absorb_unchecked(&self.transcript[old_len..]);
        self.safe.absorb(input)?;

        Ok(())
    }

    /// Ratchet the verifier's state.
    #[inline(always)]
    pub fn ratchet(&mut self) -> Result<(), IOPatternError> {
        self.safe.ratchet()
    }

    /// Return a reference to the random number generator associated to the protocol transcript.
    #[inline(always)]
    pub fn rng(&mut self) -> &mut (impl CryptoRng + RngCore) {
        &mut self.rng
    }

    /// Return the current protocol transcript.
    /// The protocol transcript does not hold eny information about the length or the type of the messages being read.
    /// This is because the information is considered pre-shared within the [`IOPattern`].
    /// Additionally, since the verifier challenges are deterministically generated from the prover's messages,
    /// the transcript does not hold any of the verifier's messages.
    pub fn transcript(&self) -> &[u8] {
        self.transcript.as_slice()
    }
}

impl<H, U, R> UnitTranscript<U> for Arthur<H, U, R>
where
    U: Unit,
    H: DuplexHash<U>,
    R: RngCore + CryptoRng,
{
    /// Add public messages to the protocol transcript.
    /// Messages input to this function are not added to the protocol transcript.
    /// They are however absorbed into the verifier's sponge for Fiat-Shamir, and used to re-seed the prover state.
    fn public_units(&mut self, input: &[U]) -> Result<(), IOPatternError> {
        let len = self.transcript.len();
        self.add_units(input)?;
        self.transcript.truncate(len);
        Ok(())
    }

    /// Fill a slice `[Arthur::U]` with challenges from the verifier.
    fn fill_challenge_units(&mut self, output: &mut [U]) -> Result<(), IOPatternError> {
        self.safe.squeeze(output)
    }
}

impl<R: RngCore + CryptoRng> CryptoRng for ProverRng<R> {}

impl<H, U, R> core::fmt::Debug for Arthur<H, U, R>
where
    U: Unit,
    H: DuplexHash<U>,
    R: RngCore + CryptoRng,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.safe.fmt(f)
    }
}

impl<H, R> ByteWriter for Arthur<H, u8, R>
where
    H: DuplexHash<u8>,
    R: RngCore + CryptoRng,
{
    #[inline(always)]
    fn add_bytes(&mut self, input: &[u8]) -> Result<(), IOPatternError> {
        self.add_units(input)
    }
}
