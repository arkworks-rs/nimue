use group::ff::PrimeField;
use super::FieldReader;
use crate::{Merlin, DuplexHash, ByteTranscriptReader};

impl<'a, F, H, const N: usize> FieldReader<F> for Merlin<'a, H>
where
    H: DuplexHash,
    F: PrimeField<Repr = [u8; N]>,
{
    fn fill_next_scalars(&mut self, output: &mut [F]) -> crate::ProofResult<()> {
        let mut buf = [0u8; N];
        for o in output.iter_mut() {
            self.fill_next_bytes(&mut buf)?;
            *o = F::from_repr(buf).unwrap();
        }
        Ok(())
    }
}

