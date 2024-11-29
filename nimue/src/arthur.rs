use crate::errors::IOPatternError;
use crate::hash::{DuplexHash, Unit};
use crate::iopattern::IOPattern;
use crate::safe::Safe;
use crate::traits::{ByteReader, UnitTranscript};
use crate::DefaultHash;

/// [`Arthur`] contains the verifier state.
///
/// Internally, it is a wrapper around a SAFE sponge.
/// Given as input an [`IOPattern`] and a protocol transcript, it allows to
/// de-serialize elements from the transcript and make them available to the zero-knowledge verifier.
pub struct Arthur<'a, H = DefaultHash, U = u8>
where
    H: DuplexHash<U>,
    U: Unit,
{
    pub(crate) safe: Safe<H, U>,
    pub(crate) transcript: &'a [u8],
}

impl<'a, U: Unit, H: DuplexHash<U>> Arthur<'a, H, U> {
    /// Creates a new [`Arthur`] instance with the given sponge and IO Pattern.
    ///
    /// The resulting object will act as the verifier in a zero-knowledge protocol.
    ///
    /// ```
    /// # use nimue::*;
    ///
    /// let io = IOPattern::<DefaultHash>::new("📝").absorb(1, "inhale 🫁").squeeze(32, "exhale 🎏");
    /// // A silly transcript for the example.
    /// let transcript = &[0x42];
    /// let mut arthur = io.to_arthur(transcript);
    /// assert_eq!(arthur.next_bytes().unwrap(), [0x42]);
    /// let challenge = arthur.challenge_bytes::<32>();
    /// assert!(challenge.is_ok());
    /// assert_ne!(challenge.unwrap(), [0; 32]);
    /// ```
    pub fn new(io_pattern: &IOPattern<H, U>, transcript: &'a [u8]) -> Self {
        let safe = Safe::new(io_pattern);
        Self { safe, transcript }
    }

    /// Read `input.len()` elements from the transcript.
    #[inline]
    pub fn fill_next_units(&mut self, input: &mut [U]) -> Result<(), IOPatternError> {
        U::read(&mut self.transcript, input)?;
        self.safe.absorb(input)?;
        Ok(())
    }

    /// Signals the end of the statement.
    #[inline]
    pub fn ratchet(&mut self) -> Result<(), IOPatternError> {
        self.safe.ratchet()
    }

    /// Signals the end of the statement and returns the (compressed) sponge state.
    #[inline]
    pub fn preprocess(self) -> Result<&'static [U], IOPatternError> {
        self.safe.preprocess()
    }
}

impl<H: DuplexHash<U>, U: Unit> UnitTranscript<U> for Arthur<'_, H, U> {
    /// Add native elements to the sponge without writing them to the protocol transcript.
    #[inline]
    fn public_units(&mut self, input: &[U]) -> Result<(), IOPatternError> {
        self.safe.absorb(input)
    }

    /// Get a challenge of `count` elements.
    #[inline]
    fn fill_challenge_units(&mut self, input: &mut [U]) -> Result<(), IOPatternError> {
        self.safe.squeeze(input)
    }
}

impl<H: DuplexHash<U>, U: Unit> core::fmt::Debug for Arthur<'_, H, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Arthur").field(&self.safe).finish()
    }
}

impl<H: DuplexHash<u8>> ByteReader for Arthur<'_, H, u8> {
    /// Read the next `input.len()` bytes from the transcript and return them.
    #[inline]
    fn fill_next_bytes(&mut self, input: &mut [u8]) -> Result<(), IOPatternError> {
        self.fill_next_units(input)
    }
}
