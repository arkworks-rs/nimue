use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use super::{FieldReader, GroupReader};
use crate::traits::*;
use crate::{DuplexHash, Merlin, ProofResult};

impl<'a, F, H> FieldReader<F> for Merlin<'a, H>
where
    F: PrimeField,
    H: DuplexHash,
{
    fn fill_next_scalars(&mut self, output: &mut [F]) -> ProofResult<()> {
        let point_size = F::default().compressed_size();
        let mut buf = vec![0u8; point_size];
        for o in output.iter_mut() {
            self.fill_next_bytes(&mut buf)?;
            *o = F::deserialize_compressed(buf.as_slice())?;
        }
        Ok(())
    }
}

impl<'a, G, H> GroupReader<G> for Merlin<'a, H>
where
    G: CurveGroup,
    H: DuplexHash,
{
    fn fill_next_points(&mut self, output: &mut [G]) -> ProofResult<()> {
        let point_size = G::default().compressed_size();
        let mut buf = vec![0u8; point_size];

        for o in output.iter_mut() {
            self.fill_next(&mut buf)?;
            *o = G::deserialize_compressed(buf.as_slice())?;
        }
        Ok(())
    }
}
