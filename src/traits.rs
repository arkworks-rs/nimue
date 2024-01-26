use crate::errors::IOPatternError;

pub trait ByteTranscript {
    fn public_bytes(&mut self, input: &[u8]) -> Result<(), IOPatternError>;

    fn fill_challenge_bytes(&mut self, output: &mut [u8]) -> Result<(), IOPatternError>;

    #[inline(always)]
    fn challenge_bytes<const N: usize>(&mut self) -> Result<[u8; N], IOPatternError> {
        let mut output = [0u8; N];
        self.fill_challenge_bytes(&mut output).map(|()| output)
    }
}

pub trait ByteTranscriptReader {
    fn fill_next_bytes(&mut self, input: &mut [u8]) -> Result<(), IOPatternError>;

    #[inline(always)]
    fn next_bytes<const N: usize>(&mut self) -> Result<[u8; N], IOPatternError> {
        let mut input = [0u8; N];
        self.fill_next_bytes(&mut input).map(|()| input)
    }
}

pub trait ByteTranscriptWriter {
    fn add_bytes(&mut self, input: &[u8]) -> Result<(), IOPatternError>;
}

pub trait ByteIOPattern {
    fn add_bytes(self, count: usize, label: &str) -> Self;
    fn challenge_bytes(self, count: usize, label: &str) -> Self;
}
