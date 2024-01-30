use group::{ff::PrimeField, Group, GroupEncoding};
use rand::{CryptoRng, RngCore};

use super::{FieldPublic, FieldWriter, GroupPublic, GroupWriter};
use crate::{Arthur, ByteWriter, DuplexHash, ProofResult};

impl<F, H, R> FieldWriter<F> for Arthur<H, u8, R>
where
    F: PrimeField,
    H: DuplexHash,
    R: RngCore + CryptoRng,
{
    fn add_scalars(&mut self, input: &[F]) -> ProofResult<()> {
        let serialized = self.public_scalars(input);
        self.transcript.extend(serialized?);
        Ok(())
    }
}

impl<G, H, R, const N: usize> GroupPublic<G> for Arthur<H, u8, R>
where
    G: Group + GroupEncoding<Repr = [u8; N]>,
    H: DuplexHash,
    R: RngCore + CryptoRng,
{
    type Repr = Vec<u8>;
    fn public_points(&mut self, input: &[G]) -> crate::ProofResult<Self::Repr> {
        let mut buf = Vec::new();
        for p in input.iter() {
            buf.extend_from_slice(&<G as GroupEncoding>::to_bytes(p));
        }
        self.add_bytes(&buf)?;
        Ok(buf)
    }
}

impl<G, H, R, const N: usize> GroupWriter<G> for Arthur<H, u8, R>
where
    G: Group + GroupEncoding<Repr = [u8; N]>,
    H: DuplexHash,
    R: RngCore + CryptoRng,
{
    fn add_points(&mut self, input: &[G]) -> crate::ProofResult<()> {
        let serialized = self.public_points(input);
        self.transcript.extend(serialized?);
        Ok(())
    }
}
