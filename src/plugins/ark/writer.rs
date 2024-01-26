use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use rand::{CryptoRng, RngCore};

use super::{FieldPublic, FieldWriter, GroupPublic, GroupWriter};
use crate::{Arthur, DuplexHash, ProofResult};

impl<F: PrimeField, H: DuplexHash, R: RngCore + CryptoRng> FieldWriter<F> for Arthur<H, R> {
    fn add_scalars(&mut self, input: &[F]) -> ProofResult<()> {
        let serialized = self.public_scalars(input);
        self.transcript.extend(serialized?);
        Ok(())
    }
}

impl<G, H, R> GroupWriter<G> for Arthur<H, R>
where
    G: CurveGroup,
    H: DuplexHash,
    R: rand::RngCore + CryptoRng,
{
    #[inline(always)]
    fn add_points(&mut self, input: &[G]) -> ProofResult<()> {
        let serialized = self.public_points(input);
        self.transcript.extend(serialized?);
        Ok(())
    }
}
