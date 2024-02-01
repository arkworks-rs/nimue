use crate::errors::IOPatternError;
use crate::Unit;

pub trait UnitTranscript<U: Unit> {
    fn public_units(&mut self, input: &[U]) -> Result<(), IOPatternError>;

    fn fill_challenge_units(&mut self, output: &mut [U]) -> Result<(), IOPatternError>;
}

pub trait BytePublic {
    fn public_bytes(&mut self, input: &[u8]) -> Result<(), IOPatternError>;
}

pub trait ByteChallenges {
    fn fill_challenge_bytes(&mut self, output: &mut [u8]) -> Result<(), IOPatternError>;

    #[inline(always)]
    fn challenge_bytes<const N: usize>(&mut self) -> Result<[u8; N], IOPatternError> {
        let mut output = [0u8; N];
        self.fill_challenge_bytes(&mut output).map(|()| output)
    }
}

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
