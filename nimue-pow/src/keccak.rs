use super::PowStrategy;

#[derive(Clone, Copy)]
pub struct KeccakPoW {
    challenge: [u64; 4],
    threshold: u64,
    state: [u64; 25],
}

impl PowStrategy for KeccakPoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        let threshold = (64.0 - bits).exp2().ceil() as u64;
        Self {
            challenge: bytemuck::cast(challenge),
            threshold,
            state: [0; 25],
        }
    }

    fn check(&mut self, nonce: u64) -> bool {
        self.state[..4].copy_from_slice(&self.challenge);
        self.state[4] = nonce;
        for s in self.state.iter_mut().skip(5) {
            *s = 0;
        }
        keccak::f1600(&mut self.state);
        self.state[0] < self.threshold
    }
}

#[test]
fn test_pow_keccak() {
    use crate::{ByteIOPattern, ByteReader, ByteWriter, PoWChallenge, PoWIOPattern};
    use nimue::{DefaultHash, IOPattern};

    const BITS: f64 = 10.0;

    let iopattern = IOPattern::<DefaultHash>::new("the proof of work lottery 🎰")
        .add_bytes(1, "something")
        .challenge_pow("rolling dices");

    let mut prover = iopattern.to_merlin();
    prover.add_bytes(b"\0").expect("Invalid IOPattern");
    prover.challenge_pow::<KeccakPoW>(BITS).unwrap();

    let mut verifier = iopattern.to_arthur(prover.transcript());
    let byte = verifier.next_bytes::<1>().unwrap();
    assert_eq!(&byte, b"\0");
    verifier.challenge_pow::<KeccakPoW>(BITS).unwrap();
}
