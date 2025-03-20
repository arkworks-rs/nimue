use group::{ff::PrimeField, Group, GroupEncoding};
use rand::{CryptoRng, RngCore};

use super::{CommonFieldToUnit, FieldToUnit, CommonGroupToUnit, GroupToUnit};
use crate::{ByteWriter, DuplexSpongeInterface, ProofResult, ProverPrivateState, CommonProverMessageBytes};

impl<F, H, R> FieldToUnit<F> for ProverPrivateState<H, u8, R>
where
    F: PrimeField,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    fn add_scalars(&mut self, input: &[F]) -> ProofResult<()> {
        let serialized = self.public_scalars(input);
        self.narg_string.extend(serialized?);
        Ok(())
    }
}

impl<G, H, R> CommonGroupToUnit<G> for ProverPrivateState<H, u8, R>
where
    G: Group + GroupEncoding,
    G::Repr: AsRef<[u8]>,
    H: DuplexSpongeInterface,
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

impl<G, H, R> GroupToUnit<G> for ProverPrivateState<H, u8, R>
where
    G: Group + GroupEncoding,
    G::Repr: AsRef<[u8]>,
    H: DuplexSpongeInterface,
    R: RngCore + CryptoRng,
{
    fn add_points(&mut self, input: &[G]) -> crate::ProofResult<()> {
        let serialized = self.public_points(input);
        self.narg_string.extend(serialized?);
        Ok(())
    }
}


impl<F, T> CommonFieldToUnit<F> for T
where
    F: PrimeField,
    T: CommonProverMessageBytes,
{
    type Repr = Vec<u8>;

    fn public_scalars(&mut self, input: &[F]) -> ProofResult<Self::Repr> {
        let mut buf = Vec::new();
        input.iter().for_each(|i| buf.extend(i.to_repr().as_ref()));
        self.public_bytes(&buf)?;
        Ok(buf)
    }
}
