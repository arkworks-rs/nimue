use rand::{Rng, SeedableRng};

use crate::{
    Arthur, ByteChallenges, ByteIOPattern, ByteReader, ByteWriter, IOPattern, Merlin, ProofError,
    ProofResult,
};

/// Struct describing the number of bits of proof of work required
/// Must be between 0 and 128 bits
pub struct POWBits(u8);

impl POWBits {
    /// Constructs a `POWBits` object.
    /// Panics if `bits >= 128`.
    pub fn new(bits: u8) -> Self {
        assert!(bits < 128);
        POWBits(bits)
    }
}

/// The nonce for a proof-of-work-challenge
pub struct POWNonce(pub [u8; 16]);

pub trait POWIOPatter {
    // TODO: Do we want to add bits in the label at trait level?
    fn challenge_pow(self, label: &str) -> Self;
}

impl POWIOPatter for IOPattern {
    fn challenge_pow(self, label: &str) -> Self {
        // 16 bytes challenge and 16 bytes nonce (that will be written)
        self.challenge_bytes(16, label).add_bytes(16, label)
    }
}

pub trait POWChallenge {
    fn challenge_pow(&mut self, bits: POWBits) -> ProofResult<POWNonce>;
}

fn increment(challenge: [u8; 16]) -> [u8; 16] {
    let mut res = [0u8; 16];
    res.copy_from_slice(&(u128::from_be_bytes(challenge) + 1).to_be_bytes());
    res
}

impl POWChallenge for Merlin
where
    Merlin: ByteWriter,
{
    fn challenge_pow(&mut self, bits: POWBits) -> ProofResult<POWNonce> {
        // Squeeze 16 bytes as a challenge from the spong
        let mut seed = [0u8; 32];
        self.fill_challenge_bytes(&mut seed[..16])?;

        // Loop to find a 16-byte nonce
        let mut counter = [0u8; 16];
        loop {
            // Seed rng with the 32-byte (challenge + nonce) seed
            seed[16..].copy_from_slice(&counter);
            let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
            let num: u64 = rng.gen();
            if num < (1 << bits.0) {
                // Add to the transcript the nonce
                self.add_bytes(&counter)?;
                return Ok(POWNonce(counter));
            }
            counter = increment(counter);
        }
    }
}

impl<'a> POWChallenge for Arthur<'a>
where
    Arthur<'a>: ByteReader,
{
    fn challenge_pow(&mut self, bits: POWBits) -> ProofResult<POWNonce> {
        // Get the 32 byte seed
        let mut seed = [0u8; 32];
        self.fill_challenge_bytes(&mut seed[..16])?;
        let counter: [u8; 16] = self.next_bytes()?;
        seed[16..].copy_from_slice(&counter);

        // Instantiate rng and verify.
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        let num: u64 = rng.gen();

        if num < (1 << bits.0) {
            Ok(POWNonce(counter))
        } else {
            Err(ProofError::InvalidProof)
        }
    }
}
