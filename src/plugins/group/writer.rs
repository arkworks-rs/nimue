use crate::DuplexHash;
use group::ff::PrimeField;
use rand::{CryptoRng, RngCore};

use super::{FieldPublic, FieldWriter};
use crate::{Arthur, ProofResult};

impl<F: PrimeField, H: DuplexHash, R: RngCore + CryptoRng> FieldWriter<F> for Arthur<H, R> {
    fn add_scalars(&mut self, input: &[F]) -> ProofResult<()> {
        let serialized = self.public_scalars(input);
        self.transcript.extend(serialized?);
        Ok(())
    }
}
