use crate::{
    hash::Keccak, Arthur, ByteChallenges, ByteIOPattern, ByteReader, ByteWriter, DuplexHash,
    IOPattern, Merlin, ProofError, ProofResult,
};
#[cfg(feature = "parallel")]
use {
    rayon::broadcast,
    std::sync::atomic::{AtomicU64, Ordering},
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
    fn challenge_pow(&mut self, bits: usize) -> ProofResult<()>;
}

impl PoWChallenge for Merlin
where
    Merlin: ByteWriter,
{
    fn challenge_pow(&mut self, bits: usize) -> ProofResult<()> {
        let challenge = self.challenge_bytes()?;
        let nonce = Pow::new(challenge, bits as f64)
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
    fn challenge_pow(&mut self, bits: usize) -> ProofResult<()> {
        let challenge = self.challenge_bytes()?;
        let nonce = u64::from_be_bytes(self.next_bytes()?);
        if Pow::new(challenge, bits as f64).check(nonce) {
            Ok(())
        } else {
            Err(ProofError::InvalidProof)
        }
    }
}

#[derive(Clone, Copy)]
struct Pow {
    challenge: [u8; 32],
    bits: usize,
}

impl Pow {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        Self {
            challenge,
            bits: bits as usize,
        }
    }

    fn check(&mut self, nonce: u64) -> bool {
        let mut chal_bytes = [0u8; 16];
        Keccak::new(self.challenge)
            .absorb_unchecked(&nonce.to_be_bytes())
            .squeeze_unchecked(&mut chal_bytes);
        let chal = u128::from_be_bytes(chal_bytes);
        (chal << self.bits) >> self.bits == chal
    }

    /// Finds the minimal `nonce` that satisfies the challenge.
    #[cfg(not(feature = "parallel"))]
    fn solve(&mut self) -> Option<u64> {
        (0u64..).find(|n| self.check(n))
    }

    /// Finds the minimal `nonce` that satisfies the challenge.
    #[cfg(feature = "parallel")]
    fn solve(&mut self) -> Option<u64> {
        // Split the work across all available threads.
        // Use atomics to find the unique deterministic lowest satisfying nonce.
        let global_min = AtomicU64::new(u64::MAX);
        let _ = broadcast(|ctx| {
            let mut worker = self.clone();
            let nonces = (ctx.index() as u64..).step_by(ctx.num_threads());
            for nonce in nonces {
                // Use relaxed ordering to eventually get notified of another thread's solution.
                // (Propagation delay should be in the order of tens of nanoseconds.)
                if nonce >= global_min.load(Ordering::Relaxed) {
                    break;
                }
                if worker.check(nonce) {
                    // We found a solution, store it in the global_min.
                    // Use fetch_min to solve race condition with simultaneous solutions.
                    global_min.fetch_min(nonce, Ordering::SeqCst);
                    break;
                }
            }
        });
        match global_min.load(Ordering::SeqCst) {
            u64::MAX => self.check(u64::MAX).then_some(u64::MAX),
            nonce => Some(nonce),
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
    prover.challenge_pow(5).unwrap();

    let mut verifier = iopattern.to_arthur(prover.transcript());
    let byte = verifier.next_bytes::<1>().unwrap();
    assert_eq!(&byte, b"\0");
    verifier.challenge_pow(5).unwrap();
}
