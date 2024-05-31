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

fn prepare_keccak_buf(challenge: &[u8; 16], counter: &[u8; 16]) -> [u64; 25] {
    let mut buf = [0xdeadbeef; 25];

    for i in 0..2 {
        let mut temp = [0u8; 8];
        temp.copy_from_slice(&challenge[i..i + 8]);
        buf[i] = u64::from_be_bytes(temp);

        temp.copy_from_slice(&counter[i..i + 8]);
        buf[2 + i] = u64::from_be_bytes(temp);
    }

    buf
}

impl POWChallenge for Merlin
where
    Merlin: ByteWriter,
{
    fn challenge_pow(&mut self, bits: POWBits) -> ProofResult<POWNonce> {
        // Squeeze 16 bytes as a challenge from the spong
        let mut challenge = [0u8; 16];
        self.fill_challenge_bytes(&mut challenge)?;

        // Loop to find a 16-byte nonce
        let mut counter = [0u8; 16];
        loop {
            // Seed rng with the 32-byte (challenge + nonce) seed
            let mut keccak_buf = prepare_keccak_buf(&challenge, &counter);
            keccak::f1600(&mut keccak_buf);
            let num = keccak_buf[0];
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
        let mut challenge = [0u8; 16];
        self.fill_challenge_bytes(&mut challenge)?;
        let counter: [u8; 16] = self.next_bytes()?;

        // Instantiate keccak and verify.
        let mut keccak_buf = prepare_keccak_buf(&challenge, &counter);
        keccak::f1600(&mut keccak_buf);
        let num = keccak_buf[0];

        if num < (1 << bits.0) {
            Ok(POWNonce(counter))
        } else {
            Err(ProofError::InvalidProof)
        }
    }
}
