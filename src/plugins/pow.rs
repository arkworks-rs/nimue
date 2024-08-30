use std::u64;

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
    fn challenge_pow(&mut self, bits: f64) -> ProofResult<()>;
}

impl PoWChallenge for Merlin
where
    Merlin: ByteWriter,
{
    fn challenge_pow(&mut self, bits: f64) -> ProofResult<()> {
        let challenge = self.challenge_bytes()?;
        let nonce = Pow::new(challenge, bits)
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
    fn challenge_pow(&mut self, bits: f64) -> ProofResult<()> {
        let challenge = self.challenge_bytes()?;
        let nonce = u64::from_be_bytes(self.next_bytes()?);
        if Pow::new(challenge, bits).check(nonce) {
            Ok(())
        } else {
            Err(ProofError::InvalidProof)
        }
    }
}

#[derive(Clone, Copy)]
struct Pow {
    challenge: [u8; 32],
    threshold: u64,
}

impl Pow {
    /// Creates a new proof-of-work challenge.
    /// The `challenge` is a 32-byte array that represents the challenge.
    /// The `bits` is the binary logarithm of the expected amount of work.
    /// When `bits` is large (i.e. close to 64), a valid solution may not be found.
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        let threshold = (64.0 - bits).exp2().ceil() as u64;
        Self {
            challenge,
            threshold,
        }
    }

    fn check(&mut self, nonce: u64) -> bool {
        let mut chal_bytes = [0u8; 8];
        Keccak::new(self.challenge)
            .absorb_unchecked(&nonce.to_le_bytes())
            .squeeze_unchecked(&mut chal_bytes);
        u64::from_le_bytes(chal_bytes) < self.threshold
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
    prover.challenge_pow(15.5).unwrap();

    let mut verifier = iopattern.to_arthur(prover.transcript());
    let byte = verifier.next_bytes::<1>().unwrap();
    assert_eq!(&byte, b"\0");
    verifier.challenge_pow(15.5).unwrap();
}
