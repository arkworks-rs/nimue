use crate::{ByteTranscript, ProofResult};
use group::ff::PrimeField;

use super::{FieldChallenges, FieldPublic};
use crate::plugins::bytes_uniform_modp;

fn from_bytes_mod_order<F: PrimeField>(bytes: &[u8]) -> F {
    let two = F::ONE + F::ONE;
    let basis = two.pow(&[64]);
    let mut iterator = bytes.chunks_exact(8);
    let mut acc = F::ZERO;

    while let Some(chunk) = iterator.next() {
        let chunk = u64::from_be_bytes(chunk.try_into().unwrap());
        acc = acc * basis + F::from(chunk);
    }
    let reminder = iterator.remainder();
    let reminder = u64::from_be_bytes(reminder.try_into().unwrap());
    acc = acc * basis + F::from(reminder);

    acc
}

impl<F, T> FieldChallenges<F> for T
where
    F: PrimeField,
    T: ByteTranscript,
{
    fn fill_challenge_scalars(&mut self, output: &mut [F]) -> ProofResult<()> {
        let mut buf = vec![0; bytes_uniform_modp(F::NUM_BITS)];

        for o in output {
            self.fill_challenge_bytes(&mut buf)?;
            *o = from_bytes_mod_order(&buf);
        }

        Ok(())
    }
}

impl<F, T> FieldPublic<F> for T
where
    F: PrimeField,
    T: ByteTranscript,
{
    type Repr = Vec<u8>;

    fn public_scalars(&mut self, input: &[F]) -> ProofResult<Self::Repr> {
        let mut buf = Vec::new();
        input.iter().for_each(|i| buf.extend(i.to_repr().as_ref()));
        self.public_bytes(&buf)?;
        Ok(buf)
    }
}
