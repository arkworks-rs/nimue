use core::borrow::Borrow;

use rand::{CryptoRng, RngCore};

use super::keccak::Keccak;
use super::{DefaultRng, Duplexer, IOPattern, InvalidTag, Merlin};

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
pub struct ArthurBuilder<S: Duplexer>
where
    S: Duplexer,
{
    merlin: Merlin<S>,
    u8sponge: Keccak,
}

impl<S: Duplexer> ArthurBuilder<S> {
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
    pub fn finalize_with_rng<R: RngCore + CryptoRng>(self, csrng: R) -> Arthur<S, R> {
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

impl<S: Duplexer, B: Borrow<IOPattern>> From<B> for Arthur<S> {
    fn from(pattern: B) -> Self {
        ArthurBuilder::new(pattern.borrow()).finalize_with_rng(DefaultRng::default())
    }
}

/// The state of an interactive proof system.
/// Holds the state of the verifier, and provides the random coins for the prover.
pub struct Arthur<S, R = DefaultRng>
where
    S: Duplexer,
    R: RngCore + CryptoRng,
{
    /// The randomness state of the prover.
    pub(crate) arthur: ProverRng<R>,
    pub(crate) merlin: Merlin<S>,
}




impl<S: Duplexer, R: RngCore + CryptoRng> Arthur<S, R> {
    pub fn new(io_pattern: &IOPattern, csrng: R) -> Self {
        ArthurBuilder::new(io_pattern).finalize_with_rng(csrng)
    }

    #[inline]
    pub fn append(&mut self, input: &[S::L]) -> Result<Vec<u8>, InvalidTag> {
        let serialized = bincode::serialize(input).unwrap();
        self.arthur.sponge.absorb_unchecked(&serialized);
        self.merlin.append(input)?;

        Ok(serialized)
    }

    /// Get a challenge of `count` bytes.
    pub fn challenge_bytes(&mut self, dest: &mut [u8]) -> Result<(), InvalidTag> {
        self.merlin.challenge_bytes(dest)?;
        Ok(())
    }

    #[inline]
    pub fn process(&mut self) -> Result<(), InvalidTag> {
        self.merlin.process().map(|_| ())
    }

    #[inline]
    pub fn rng<'a>(&'a mut self) -> &'a mut (impl CryptoRng + RngCore) {
        &mut self.arthur
    }
}

impl<R: RngCore + CryptoRng> CryptoRng for ProverRng<R> {}

impl<S: Duplexer, R: RngCore + CryptoRng> ::core::fmt::Debug for Arthur<S, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.merlin.fmt(f)
    }
}
