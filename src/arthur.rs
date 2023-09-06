use rand::{CryptoRng, RngCore};

use crate::hash::Unit;
use crate::IOPattern;

use super::hash::{DuplexHash, Keccak};
use super::{DefaultHash, DefaultRng, InvalidTag, Merlin};
/// Arthur is a cryptographically-secure random number generator that is bound to the protocol transcript.
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

/// Builder for the prover state.
pub struct ArthurBuilder<S: DuplexHash<U = U>, U: Unit>
where
    S: DuplexHash,
{
    merlin: Merlin<S, U>,
    u8sponge: Keccak,
}

impl<H: DuplexHash<U = U>, U: Unit> ArthurBuilder<H, U> {
    pub(crate) fn new(io_pattern: &IOPattern<H>) -> Self {
        let merlin = Merlin::new(io_pattern);

        let mut u8sponge = Keccak::default();
        u8sponge.absorb_unchecked(io_pattern.as_bytes());

        Self { u8sponge, merlin }
    }

    // rekey the private sponge with some additional secrets (i.e. with the witness)
    // and divide
    pub fn rekey(mut self, data: &[u8]) -> Self {
        self.u8sponge.absorb_unchecked(data);
        self.u8sponge.ratchet_unchecked();
        self
    }

    // Finalize the state integrating a cryptographically-secure
    // random number generator that will be used to seed the state before future squeezes.
    pub fn finalize_with_rng<R: RngCore + CryptoRng>(self, csrng: R) -> Arthur<H, R, H::U> {
        let arthur = ProverRng {
            sponge: self.u8sponge,
            csrng,
        };

        Arthur {
            merlin: self.merlin,
            arthur,
        }
    }
}

impl<R: RngCore + CryptoRng + Default, H: DuplexHash> From<&IOPattern<H>> for Arthur<H, R, H::U> {
    fn from(pattern: &IOPattern<H>) -> Self {
        ArthurBuilder::new(pattern).finalize_with_rng(R::default())
    }
}

/// The state of an interactive proof system.
/// Holds the state of the verifier, and provides the random coins for the prover.
pub struct Arthur<H = DefaultHash, R = DefaultRng, U = u8>
where
    H: DuplexHash<U = U>,
    R: RngCore + CryptoRng,
    U: Unit,
{
    /// The randomness state of the prover.
    pub(crate) arthur: ProverRng<R>,
    pub(crate) merlin: Merlin<H, H::U>,
}

impl<R: RngCore + CryptoRng, H: DuplexHash> Arthur<H, R, H::U> {
    pub fn new(io_pattern: &IOPattern<H>, csrng: R) -> Self {
        ArthurBuilder::new(io_pattern).finalize_with_rng(csrng)
    }

    #[inline]
    pub fn absorb_native(&mut self, input: &[H::U]) -> Result<(), InvalidTag> {
        // let serialized = bincode::serialize(input).unwrap();
        // self.arthur.sponge.absorb_unchecked(&serialized);
        self.merlin.absorb_native(input)?;

        Ok(())
    }

    #[inline]
    pub fn ratchet(&mut self) -> Result<(), InvalidTag> {
        self.merlin.ratchet()
    }

    #[inline]
    pub fn rng<'a>(&'a mut self) -> &'a mut (impl CryptoRng + RngCore) {
        &mut self.arthur
    }
}

impl<R: RngCore + CryptoRng> CryptoRng for ProverRng<R> {}

impl<R: RngCore + CryptoRng, H: DuplexHash> ::core::fmt::Debug for Arthur<H, R, H::U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.merlin.fmt(f)
    }
}

impl<H: DuplexHash<U = u8>, R: RngCore + CryptoRng> Arthur<H, R, u8> {
    pub fn absorb_bytes(&mut self, input: &[u8]) -> Result<(), InvalidTag> {
        self.absorb_native(input)
    }

    pub fn squeeze_bytes(&mut self, output: &mut [u8]) -> Result<(), InvalidTag> {
        self.merlin.squeeze_native(output)
    }
}
