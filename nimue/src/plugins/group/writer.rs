use group::{ff::PrimeField, Group, GroupEncoding};
use rand::{CryptoRng, RngCore};

use super::{FieldPublic, FieldWriter, GroupPublic, GroupWriter};
use crate::{ByteWriter, DuplexHash, Merlin, ProofResult};

impl<F, H, R> FieldWriter<F> for Merlin<H, u8, R>
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

impl<G, H, R> GroupPublic<G> for Merlin<H, u8, R>
where
    G: Group + GroupEncoding,
    G::Repr: AsRef<[u8]>,
    H: DuplexHash,
    R: RngCore + CryptoRng,
{
    type Repr = Vec<u8>;
    fn public_points(&mut self, input: &[G]) -> crate::ProofResult<Self::Repr> {
        let mut buf = Vec::new();
        for p in input.iter() {
            buf.extend_from_slice(&<G as GroupEncoding>::to_bytes(p).as_ref());
        }
        self.add_bytes(&buf)?;
        Ok(buf)
    }
}

impl<G, H, R> GroupWriter<G> for Merlin<H, u8, R>
where
    G: Group + GroupEncoding,
    G::Repr: AsRef<[u8]>,
    H: DuplexHash,
    R: RngCore + CryptoRng,
{
    fn add_points(&mut self, input: &[G]) -> crate::ProofResult<()> {
        let serialized = self.public_points(input);
        self.transcript.extend(serialized?);
        Ok(())
    }
}
