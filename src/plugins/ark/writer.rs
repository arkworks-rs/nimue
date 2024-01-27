use ark_ec::CurveGroup;
use ark_ff::{Fp, FpConfig, PrimeField};
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
    R: RngCore + CryptoRng,
    Arthur<H, R>: GroupPublic<G, Repr = Vec<u8>>,
{
    #[inline(always)]
    fn add_points(&mut self, input: &[G]) -> ProofResult<()> {
        let serialized = self.public_points(input);
        self.transcript.extend(serialized?);
        Ok(())
    }
}

impl<G, H, R, C: FpConfig<N>, const N: usize> GroupWriter<G> for Arthur<H, R, Fp<C, N>>
where
    G: CurveGroup,
    H: DuplexHash<Fp<C, N>>,
    R: RngCore + CryptoRng,
    Arthur<H, R, Fp<C, N>>: GroupPublic<G>,
{
    #[inline(always)]
    fn add_points(&mut self, input: &[G]) -> ProofResult<()> {
        self.public_points(input).map(|_| ())?;
        for i in input {
            i.serialize_compressed(&mut self.transcript)?;
        }
        Ok(())
    }
}
