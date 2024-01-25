use rand::{CryptoRng, RngCore};

use crate::hash::Unit;
use crate::{ByteTranscript, ByteTranscriptWriter, IOPattern, Safe};

use super::hash::{DuplexHash, Keccak};
use super::{DefaultHash, DefaultRng, IOPatternError};

/// A cryptographically-secure random number generator that is bound to the protocol transcript.
///
/// For most public-coin protocols it is *vital* not to have two commitments for the same challenge.
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

impl<H, R, U> Arthur<H, R, U>
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

impl<U, H, D> From<D> for Arthur<H, DefaultRng, U>
where
    U: Unit,
    H: DuplexHash<U>,
    D: core::ops::Deref<Target = IOPattern<H, U>>,
{
    fn from(pattern: D) -> Self {
        Arthur::new(pattern.deref(), DefaultRng::default())
    }
}

/// The state of an interactive proof system.
/// Holds the state of the verifier, and provides the random coins for the prover.
pub struct Arthur<H = DefaultHash, R = DefaultRng, U = u8>
where
    H: DuplexHash<U>,
    R: RngCore + CryptoRng,
    U: Unit,
{
    /// The randomness state of the prover.
    pub(crate) rng: ProverRng<R>,
    /// The public coins for the protocol
    pub(crate) safe: Safe<H, U>,
    /// The encoded data.
    pub(crate) transcript: Vec<u8>,
}

impl<R: RngCore + CryptoRng, U: Unit, H: DuplexHash<U>> Arthur<H, R, U> {
    #[inline(always)]
    pub fn add(&mut self, input: &[U]) -> Result<(), IOPatternError> {
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

    pub fn public(&mut self, input: &[U]) -> Result<(), IOPatternError> {
        let len = self.transcript.len();
        self.add(input)?;
        self.transcript.truncate(len);
        Ok(())
    }

    pub fn fill_challenges(&mut self, output: &mut [U]) -> Result<(), IOPatternError> {
        self.safe.squeeze(output)
    }

    #[inline(always)]
    pub fn ratchet(&mut self) -> Result<(), IOPatternError> {
        self.safe.ratchet()
    }

    #[inline(always)]
    pub fn rng(&mut self) -> &mut (impl CryptoRng + RngCore) {
        &mut self.rng
    }

    pub fn transcript(&self) -> &[u8] {
        self.transcript.as_slice()
    }
}

impl<R: RngCore + CryptoRng> CryptoRng for ProverRng<R> {}

impl<R: RngCore + CryptoRng, U: Unit, H: DuplexHash<U>> core::fmt::Debug for Arthur<H, R, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.safe.fmt(f)
    }
}

impl<H: DuplexHash, R: RngCore + CryptoRng> ByteTranscript for Arthur<H, R> {
    #[inline(always)]
    fn public_bytes(&mut self, input: &[u8]) -> Result<(), IOPatternError> {
        self.public(input)
    }

    #[inline(always)]
    fn fill_challenge_bytes(&mut self, output: &mut [u8]) -> Result<(), IOPatternError> {
        self.fill_challenges(output)
    }
}

impl<H: DuplexHash, R: RngCore + CryptoRng> ByteTranscriptWriter for Arthur<H, R> {
    #[inline(always)]
    fn add_bytes(&mut self, input: &[u8]) -> Result<(), IOPatternError> {
        self.add(input)
    }
}
