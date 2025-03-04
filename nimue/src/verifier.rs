use crate::duplex_sponge::{DuplexInterface, Unit};
use crate::errors::DomainSeparatorMismatch;
use crate::domain_separator::DomainSeparator;
use crate::sho::StatefulHashObject;
use crate::traits::{ByteReader, UnitTranscript};
use crate::DefaultHash;

/// [`VerifierState`] contains the verifier state.
///
/// Internally, it simply contains a stateful hash.
/// Given as input an [`DomainSeparator`] and a protocol transcript, it allows to
/// de-serialize elements from the transcript and make them available to the zero-knowledge verifier.
pub struct VerifierState<'a, H = DefaultHash, U = u8>
where
    H: DuplexInterface<U>,
    U: Unit,
{
    pub(crate) sho: StatefulHashObject<H, U>,
    pub(crate) transcript: &'a [u8],
}

impl<'a, U: Unit, H: DuplexInterface<U>> VerifierState<'a, H, U> {
    /// Creates a new [`VerifierState`] instance with the given sponge and IO Pattern.
    ///
    /// The resulting object will act as the verifier in a zero-knowledge protocol.
    ///
    /// ```
    /// # use nimue::*;
    ///
    /// let domsep = DomainSeparator::<DefaultHash>::new("📝").absorb(1, "inhale 🫁").squeeze(32, "exhale 🎏");
    /// // A silly transcript for the example.
    /// let transcript = &[0x42];
    /// let mut arthur = domsep.to_verifier_state(transcript);
    /// assert_eq!(arthur.next_bytes().unwrap(), [0x42]);
    /// let challenge = arthur.challenge_bytes::<32>();
    /// assert!(challenge.is_ok());
    /// assert_ne!(challenge.unwrap(), [0; 32]);
    /// ```
    pub fn new(domain_separator: &DomainSeparator<H, U>, transcript: &'a [u8]) -> Self {
        let sho = StatefulHashObject::new(domain_separator);
        Self { sho, transcript }
    }

    /// Read `input.len()` elements from the transcript.
    #[inline]
    pub fn fill_next_units(&mut self, input: &mut [U]) -> Result<(), DomainSeparatorMismatch> {
        U::read(&mut self.transcript, input)?;
        self.sho.absorb(input)?;
        Ok(())
    }

    /// Signals the end of the statement.
    #[inline]
    pub fn ratchet(&mut self) -> Result<(), DomainSeparatorMismatch> {
        self.sho.ratchet()
    }

    /// Signals the end of the statement and returns the (compressed) sponge state.
    #[inline]
    pub fn preprocess(self) -> Result<&'static [U], DomainSeparatorMismatch> {
        self.sho.preprocess()
    }
}

impl<H: DuplexInterface<U>, U: Unit> UnitTranscript<U> for VerifierState<'_, H, U> {
    /// Add native elements to the sponge without writing them to the protocol transcript.
    #[inline]
    fn public_units(&mut self, input: &[U]) -> Result<(), DomainSeparatorMismatch> {
        self.sho.absorb(input)
    }

    /// Get a challenge of `count` elements.
    #[inline]
    fn fill_challenge_units(&mut self, input: &mut [U]) -> Result<(), DomainSeparatorMismatch> {
        self.sho.squeeze(input)
    }
}

impl<H: DuplexInterface<U>, U: Unit> core::fmt::Debug for VerifierState<'_, H, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("VerifierState")
            .field(&self.sho)
            .finish()
    }
}

impl<H: DuplexInterface<u8>> ByteReader for VerifierState<'_, H, u8> {
    /// Read the next `input.len()` bytes from the transcript and return them.
    #[inline]
    fn fill_next_bytes(&mut self, input: &mut [u8]) -> Result<(), DomainSeparatorMismatch> {
        self.fill_next_units(input)
    }
}
