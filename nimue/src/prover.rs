use rand::{CryptoRng, RngCore};

use crate::duplex_sponge::Unit;
use crate::{ByteWriter, DomainSeparator, StatefulHashObject, UnitTranscript};

use super::duplex_sponge::DuplexInterface;
use super::keccak::Keccak;
use super::{DefaultHash, DefaultRng, DomainSeparatorMismatch};

/// A cryptographically-secure random number generator that is bound to the protocol transcript.
///
/// For most public-coin protocols it is *vital* not to have two different verifier messages for the same prover message.
/// For this reason, we construct a Rng that will absorb whatever the verifier absorbs, and that in addition
/// it is seeded by a cryptographic random number generator (by default, [`rand::rngs::OsRng`]).
///
/// Every time the prover's sponge is squeeze, the state of the sponge is ratcheted, so that it can't be inverted and the randomness recovered.
pub(crate) struct ProverRng<R: RngCore + CryptoRng> {
    /// The duplex sponge that is used to generate the random coins.
    pub(crate) ds: Keccak,
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
        self.ds.absorb_unchecked(&dest[..len]);
        // fill `dest` with the output of the sponge
        self.ds.squeeze_unchecked(dest);
        // erase the state from the sponge so that it can't be reverted
        self.ds.ratchet_unchecked();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.ds.squeeze_unchecked(dest);
        Ok(())
    }
}

impl<H, U, R> ProverState<H, U, R>
where
    H: DuplexInterface<U>,
    R: RngCore + CryptoRng,
    U: Unit,
{
    pub fn new(domain_separator: &DomainSeparator<H, U>, csrng: R) -> Self {
        let safe = StatefulHashObject::new(domain_separator);

        let mut sponge = Keccak::default();
        sponge.absorb_unchecked(domain_separator.as_bytes());
        let rng = ProverRng { ds: sponge, csrng };

        Self {
            rng,
            safe,
            narg_string: Vec::new(),
        }
    }
}

impl<U, H> From<&DomainSeparator<H, U>> for ProverState<H, U, DefaultRng>
where
    U: Unit,
    H: DuplexInterface<U>,
{
    fn from(domain_separator: &DomainSeparator<H, U>) -> Self {
        ProverState::new(domain_separator, DefaultRng::default())
    }
}

/// [`ProverState`] is the prover state in an interactive proof system.
/// It internally holds the secret coins of the prover for zero-knowledge, and
/// has the hash function state for the verifier state.
///
/// Unless otherwise specified,
/// [`ProverState`] is set to work over bytes with [`DefaultHash`] and
/// rely on the default random number generator [`DefaultRng`].
pub struct ProverState<H = DefaultHash, U = u8, R = DefaultRng>
where
    U: Unit,
    H: DuplexInterface<U>,
    R: RngCore + CryptoRng,
{
    /// The randomness state of the prover.
    pub(crate) rng: ProverRng<R>,
    /// The public coins for the protocol
    pub(crate) safe: StatefulHashObject<H, U>,
    /// The encoded data.
    pub(crate) narg_string: Vec<u8>,
}

impl<H, U, R> ProverState<H, U, R>
where
    U: Unit,
    H: DuplexInterface<U>,
    R: RngCore + CryptoRng,
{
    /// Add a slice `[U]` to the protocol transcript.
    /// The messages are also internally encoded in the protocol transcript,
    /// and used to re-seed the prover's random number generator.
    ///
    /// ```
    /// use nimue::{DomainSeparator, DefaultHash, ByteWriter};
    ///
    /// let domain_separator = DomainSeparator::<DefaultHash>::new("📝").absorb(20, "how not to make pasta 🤌");
    /// let mut merlin = domain_separator.to_merlin();
    /// assert!(merlin.add_bytes(&[0u8; 20]).is_ok());
    /// let result = merlin.add_bytes(b"1tbsp every 10 liters");
    /// assert!(result.is_err())
    /// ```
    #[inline(always)]
    pub fn add_units(&mut self, input: &[U]) -> Result<(), DomainSeparatorMismatch> {
        // let serialized = bincode::serialize(input).unwrap();
        // self.merlin.sponge.absorb_unchecked(&serialized);
        let old_len = self.narg_string.len();
        self.safe.absorb(input)?;
        // write never fails on Vec<u8>
        U::write(input, &mut self.narg_string).unwrap();
        self.rng
            .ds
            .absorb_unchecked(&self.narg_string[old_len..]);

        Ok(())
    }

    /// Ratchet the verifier's state.
    #[inline(always)]
    pub fn ratchet(&mut self) -> Result<(), DomainSeparatorMismatch> {
        self.safe.ratchet()
    }

    /// Return a reference to the random number generator associated to the protocol transcript.
    ///
    /// ```
    /// # use nimue::*;
    /// # use rand::RngCore;
    ///
    /// // The IO Pattern does not need to specify the private coins.
    /// let domain_separator = DomainSeparator::<DefaultHash>::new("📝");
    /// let mut merlin = domain_separator.to_merlin();
    /// assert_ne!(merlin.rng().next_u32(), 0, "You won the lottery!");
    /// let mut challenges = [0u8; 32];
    /// merlin.rng().fill_bytes(&mut challenges);
    /// assert_ne!(challenges, [0u8; 32]);
    /// ```
    #[inline(always)]
    pub fn rng(&mut self) -> &mut (impl CryptoRng + RngCore) {
        &mut self.rng
    }

    /// Return the current protocol transcript.
    /// The protocol transcript does not hold eny information about the length or the type of the messages being read.
    /// This is because the information is considered pre-shared within the [`DomainSeparator`].
    /// Additionally, since the verifier challenges are deterministically generated from the prover's messages,
    /// the transcript does not hold any of the verifier's messages.
    ///
    /// ```
    /// # use nimue::*;
    ///
    /// let domain_separator = DomainSeparator::<DefaultHash>::new("📝").absorb(8, "how to make pasta 🤌");
    /// let mut merlin = domain_separator.to_merlin();
    /// merlin.add_bytes(b"1tbsp:3l").unwrap();
    /// assert_eq!(merlin.narg_string(), b"1tbsp:3l");
    /// ```
    pub fn narg_string(&self) -> &[u8] {
        self.narg_string.as_slice()
    }
}

impl<H, U, R> UnitTranscript<U> for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexInterface<U>,
    R: RngCore + CryptoRng,
{
    /// Add public messages to the protocol transcript.
    /// Messages input to this function are not added to the protocol transcript.
    /// They are however absorbed into the verifier's sponge for Fiat-Shamir, and used to re-seed the prover state.
    ///
    /// ```
    /// # use nimue::*;
    ///
    /// let domain_separator = DomainSeparator::<DefaultHash>::new("📝").absorb(20, "how not to make pasta 🙉");
    /// let mut merlin = domain_separator.to_merlin();
    /// assert!(merlin.public_bytes(&[0u8; 20]).is_ok());
    /// assert_eq!(merlin.narg_string(), b"");
    /// ```
    fn public_units(&mut self, input: &[U]) -> Result<(), DomainSeparatorMismatch> {
        let len = self.narg_string.len();
        self.add_units(input)?;
        self.narg_string.truncate(len);
        Ok(())
    }

    /// Fill a slice with uniformly-distributed challenges from the verifier.
    fn fill_challenge_units(&mut self, output: &mut [U]) -> Result<(), DomainSeparatorMismatch> {
        self.safe.squeeze(output)
    }
}

impl<R: RngCore + CryptoRng> CryptoRng for ProverRng<R> {}

impl<H, U, R> core::fmt::Debug for ProverState<H, U, R>
where
    U: Unit,
    H: DuplexInterface<U>,
    R: RngCore + CryptoRng,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.safe.fmt(f)
    }
}

impl<H, R> ByteWriter for ProverState<H, u8, R>
where
    H: DuplexInterface<u8>,
    R: RngCore + CryptoRng,
{
    #[inline(always)]
    fn add_bytes(&mut self, input: &[u8]) -> Result<(), DomainSeparatorMismatch> {
        self.add_units(input)
    }
}
