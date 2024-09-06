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

    /// This deliberately uses the high level interface to guarantee
    /// compatibility with standard Blake3.
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
