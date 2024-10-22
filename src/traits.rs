use crate::errors::IOPatternError;
use crate::Unit;

/// Absorbing and squeezing native elements from the sponge.
///
/// This trait is typically implemented for [`Arthur`](crate::Arthur) and [`Merlin`](crate::Merlin) instances.
/// Implementors of this trait are expected to make sure that the unit type `U` matches
/// the one used by the internal sponge.
pub trait UnitTranscript<U: Unit> {
    fn public_units(&mut self, input: &[U]) -> Result<(), IOPatternError>;

    fn fill_challenge_units(&mut self, output: &mut [U]) -> Result<(), IOPatternError>;
}

/// Absorbing bytes from the sponge, without reading or writing them into the protocol transcript.
///
/// This trait is trivial for byte-oriented sponges, but non-trivial for algebraic hashes.
/// This trait implementation is **not** expected to be streaming-friendly.
///
/// For instance, in the case of algebraic sponges operating over a field $\mathbb{F}_p$, we do not expect
/// the implementation to cache field elements filling $\ceil{\log_2(p)}$ bytes.
pub trait BytePublic {
    fn public_bytes(&mut self, input: &[u8]) -> Result<(), IOPatternError>;
}

/// Squeezing bytes from the sponge.
///
/// While this trait is trivial for byte-oriented sponges, it is non-trivial for algebraic hashes.
/// In particular, the implementation of this trait is expected to provide different guarantees between units `u8`
/// and $\mathbb{F}_p$ elements:
/// - `u8` implementations are assumed to be streaming-friendly, that is: `implementor.fill_challenge_bytes(&mut out[..1]); implementor.fill_challenge_bytes(&mut out[1..]);` is expected to be equivalent to `implementor.fill_challenge_bytes(&mut out);`.
/// - $\mathbb{F}_p$ implementations are expected to provide no such guarantee. In addition, we expect the implementation to return bytes that are uniformly distributed. In particular, note that the most significant bytes of a $\mod p$ element are not uniformly distributed. The number of bytes good to be used can be discovered playing with [our scripts](https://github.com/arkworks-rs/nimue/blob/main/scripts/useful_bits_modp.py).
pub trait ByteChallenges {
    fn fill_challenge_bytes(&mut self, output: &mut [u8]) -> Result<(), IOPatternError>;

    #[inline(always)]
    fn challenge_bytes<const N: usize>(&mut self) -> Result<[u8; N], IOPatternError> {
        let mut output = [0u8; N];
        self.fill_challenge_bytes(&mut output).map(|()| output)
    }
}

/// A trait for absorbing and squeezing bytes from a sponge.
///
/// While this trait is trivial for byte-oriented sponges, some dangers lie is non-trivial for algebraic hashes.
/// We point the curious reader to the documentation of [`BytePublic`] and [`ByteChallenges`] for more details.
pub trait ByteTranscript: BytePublic + ByteChallenges {}

pub trait ByteReader {
    fn fill_next_bytes(&mut self, input: &mut [u8]) -> Result<(), IOPatternError>;

    #[inline(always)]
    fn next_bytes<const N: usize>(&mut self) -> Result<[u8; N], IOPatternError> {
        let mut input = [0u8; N];
        self.fill_next_bytes(&mut input).map(|()| input)
    }
}

pub trait ByteWriter {
    fn add_bytes(&mut self, input: &[u8]) -> Result<(), IOPatternError>;
}

/// Methods for adding bytes to the [`IOPattern`](crate::IOPattern), properly counting group elements.
pub trait ByteIOPattern {
    fn add_bytes(self, count: usize, label: &str) -> Self;
    fn challenge_bytes(self, count: usize, label: &str) -> Self;
}

impl<T: UnitTranscript<u8>> BytePublic for T {
    #[inline]
    fn public_bytes(&mut self, input: &[u8]) -> Result<(), IOPatternError> {
        self.public_units(input)
    }
}

impl<T: UnitTranscript<u8>> ByteChallenges for T {
    #[inline]
    fn fill_challenge_bytes(&mut self, output: &mut [u8]) -> Result<(), IOPatternError> {
        self.fill_challenge_units(output)
    }
}
