use super::FieldReader;
use crate::{ByteReader, DuplexHash, Arthur, ProofError};
use group::ff::PrimeField;

impl<'a, F, H, const N: usize> FieldReader<F> for Arthur<'a, H>
where
    H: DuplexHash,
    F: PrimeField<Repr = [u8; N]>,
{
    fn fill_next_scalars(&mut self, output: &mut [F]) -> crate::ProofResult<()> {
        let mut buf = [0u8; N];
        for o in output.iter_mut() {
            self.fill_next_bytes(&mut buf)?;
            *o = F::from_repr_vartime(buf).ok_or(ProofError::SerializationError)?;
        }
        Ok(())
    }
}
