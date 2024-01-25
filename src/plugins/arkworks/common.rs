use std::io;

use ark_ec::CurveGroup;
use ark_ff::{Fp, FpConfig, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};

use super::{FieldChallenges, FieldPublic, GroupPublic};
use crate::plugins::bytes_uniform_modp;
use crate::{ByteTranscript, ProofError, ProofResult};

impl<'a, F, T> FieldPublic<F> for T
where
    F: PrimeField,
    T: ByteTranscript,
{
    type Repr = Vec<u8>;

    fn public_scalars(&mut self, input: &[F]) -> ProofResult<Self::Repr> {
        let mut buf = Vec::new();
        for i in input {
            i.serialize_compressed(&mut buf)?;
        }
        self.public_bytes(&buf)?;
        Ok(buf)
    }
}

impl<F, T> FieldChallenges<F> for T
where
    F: PrimeField,
    T: ByteTranscript,
{
    fn fill_challenge_scalars(&mut self, output: &mut [F]) -> ProofResult<()> {
        let mut buf = vec![0u8; bytes_uniform_modp(F::MODULUS_BIT_SIZE as usize)];

        for o in output.iter_mut() {
            self.fill_challenge_bytes(&mut buf)?;
            *o = F::from_be_bytes_mod_order(&buf);
        }
        Ok(())
    }
}

impl<G, T> GroupPublic<G> for T
where
    G: CurveGroup,
    T: ByteTranscript,
{
    type Repr = Vec<u8>;

    fn public_points(&mut self, input: &[G]) -> ProofResult<Self::Repr> {
        let mut buf = Vec::new();
        for i in input {
            i.serialize_compressed(&mut buf)?;
        }
        Ok(self.public_bytes(&buf).map(|()| buf)?)
    }
}

impl<C: FpConfig<N>, const N: usize> crate::Unit for Fp<C, N> {
    fn write(bunch: &[Self], mut w: &mut impl io::Write) -> Result<(), io::Error> {
        for b in bunch {
            b.serialize_compressed(&mut w)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "oh no!"))?
        }
        Ok(())
    }

    fn read(mut r: &mut impl std::io::Read, bunch: &mut [Self]) -> Result<(), std::io::Error> {
        for b in bunch.iter_mut() {
            *b = ark_ff::Fp::<C, N>::deserialize_compressed(&mut r)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "oh no!"))?
        }
        Ok(())
    }
}

impl From<SerializationError> for ProofError {
    fn from(_value: SerializationError) -> Self {
        ProofError::SerializationError
    }
}
