use crate::{
    hash::Keccak, Arthur, ByteChallenges, ByteIOPattern, ByteReader, ByteWriter, DuplexHash,
    IOPattern, Merlin, ProofError, ProofResult,
};

/// Wrapper type for a challenge generated via a proof-of-work.
/// The challenge is a 128-bit integer.
pub struct PoWChal(pub u128);

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
    fn challenge_pow(&mut self, bits: usize) -> ProofResult<PoWChal>;
}

impl PoWChallenge for Merlin
where
    Merlin: ByteWriter,
{
    fn challenge_pow(&mut self, bits: usize) -> ProofResult<PoWChal> {
        // Seed a new hash with the 32-byte challenge.
        let mut challenge = [0u8; 32];
        self.fill_challenge_bytes(&mut challenge)?;
        let hash = Keccak::new(challenge);

        // Output buffer for the hash
        let mut chal_bytes = [0u8; 16];

        // Loop over a 64-bit integer to find a PoWChal sufficiently small.
        for nonce in 0u64.. {
            hash.clone()
                .absorb_unchecked(&nonce.to_be_bytes())
                .squeeze_unchecked(&mut chal_bytes);
            let chal = u128::from_be_bytes(chal_bytes);
            if (chal << bits) >> bits == chal {
                self.add_bytes(&nonce.to_be_bytes())?;
                return Ok(PoWChal(chal));
            }
        }

        // Congratulations, you wasted 2^64 Keccak calls. You're a winner.
        Err(ProofError::InvalidProof)
    }
}

impl<'a> PoWChallenge for Arthur<'a>
where
    Arthur<'a>: ByteReader,
{
    fn challenge_pow(&mut self, bits: usize) -> ProofResult<PoWChal> {
        // Re-compute the challenge and store it in chal_bytes
        let mut chal_bytes = [0u8; 16];
        let iv = self.challenge_bytes::<32>()?;
        let nonce = self.next_bytes::<8>()?;
        Keccak::new(iv)
            .absorb_unchecked(&nonce)
            .squeeze_unchecked(&mut chal_bytes);

        // Check if the challenge is valid
        let chal = u128::from_be_bytes(chal_bytes);
        if (chal << bits) >> bits == chal {
            Ok(PoWChal(chal))
        } else {
            Err(ProofError::InvalidProof)
        }
    }
}

#[test]
fn test_pow() {
    let iopattern = IOPattern::new("the proof of work lottery 🎰")
        .add_bytes(1, "something")
        .challenge_pow("rolling dices");

    let mut prover = iopattern.to_merlin();
    prover.add_bytes(b"\0").expect("Invalid IOPattern");
    let expected = prover.challenge_pow(5).unwrap();

    let mut verifier = iopattern.to_arthur(prover.transcript());
    let byte = verifier.next_bytes::<1>().unwrap();
    assert_eq!(&byte, b"\0");
    let got = verifier.challenge_pow(5).unwrap();
    assert_eq!(expected.0, got.0);
}
