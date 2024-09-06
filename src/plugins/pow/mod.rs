mod blake3;

use crate::{
    Arthur, ByteChallenges, ByteIOPattern, ByteReader, ByteWriter, IOPattern, Merlin, ProofError,
    ProofResult,
};
/// [`IOPattern`] for proof-of-work challenges.
pub trait PoWIOPattern {
    /// Adds a [`PoWChal`] to the [`IOPattern`].
    ///
    /// In order to squeeze a proof-of-work challenge, we extract a 32-byte challenge using
    /// the byte interface, and then we find a 16-byte nonce that satisfies the proof-of-work.
    /// The nonce a 64-bit integer encoded as an unsigned integer and written in big-endian and added
    /// to the protocol transcript as the nonce for the proof-of-work.
    ///
    /// The number of bits used for the proof of work are **not** encoded within the [`IOPattern`].
    /// It is up to the implementor to change the domain separator or the label in order to reflect changes in the proof
    /// in order to preserve simulation extractability.
    fn challenge_pow(self, label: &str) -> Self;
}

impl PoWIOPattern for IOPattern {
    fn challenge_pow(self, label: &str) -> Self {
        // 16 bytes challenge and 16 bytes nonce (that will be written)
        self.challenge_bytes(32, label).add_bytes(8, "pow-nonce")
    }
}

pub trait PoWChallenge {
    /// Extension trait for generating a proof-of-work challenge.
    fn challenge_pow<S: PowStrategy>(&mut self, bits: f64) -> ProofResult<()>;
}

impl PoWChallenge for Merlin
where
    Merlin: ByteWriter,
{
    fn challenge_pow<S: PowStrategy>(&mut self, bits: f64) -> ProofResult<()> {
        let challenge = self.challenge_bytes()?;
        let nonce = S::new(challenge, bits)
            .solve()
            .ok_or(ProofError::InvalidProof)?;
        self.add_bytes(&nonce.to_be_bytes())?;
        Ok(())
    }
}

impl<'a> PoWChallenge for Arthur<'a>
where
    Arthur<'a>: ByteReader,
{
    fn challenge_pow<S: PowStrategy>(&mut self, bits: f64) -> ProofResult<()> {
        let challenge = self.challenge_bytes()?;
        let nonce = u64::from_be_bytes(self.next_bytes()?);
        if S::new(challenge, bits).check(nonce) {
            Ok(())
        } else {
            Err(ProofError::InvalidProof)
        }
    }
}

pub trait PowStrategy {
    /// Creates a new proof-of-work challenge.
    /// The `challenge` is a 32-byte array that represents the challenge.
    /// The `bits` is the binary logarithm of the expected amount of work.
    /// When `bits` is large (i.e. close to 64), a valid solution may not be found.
    fn new(challenge: [u8; 32], bits: f64) -> Self;

    /// Check if the `nonce` satisfies the challenge.
    fn check(&mut self, nonce: u64) -> bool;

    /// Finds the minimal `nonce` that satisfies the challenge.
    fn solve(&mut self) -> Option<u64>;
}
