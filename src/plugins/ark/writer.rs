use ark_ec::CurveGroup;
use ark_ff::{Fp, FpConfig, PrimeField};
use ark_serialize::CanonicalSerialize;
use rand::{CryptoRng, RngCore};

use super::{FieldPublic, FieldWriter, GroupPublic, GroupWriter};
use crate::{DuplexHash, Merlin, ProofResult, UnitTranscript};

impl<F: PrimeField, H: DuplexHash, R: RngCore + CryptoRng> FieldWriter<F> for Merlin<H, u8, R> {
    fn add_scalars(&mut self, input: &[F]) -> ProofResult<()> {
        let serialized = self.public_scalars(input);
        self.transcript.extend(serialized?);
        Ok(())
    }
}

impl<C: FpConfig<N>, H: DuplexHash<Fp<C, N>>, R: RngCore + CryptoRng, const N: usize>
    FieldWriter<Fp<C, N>> for Merlin<H, Fp<C, N>, R>
{
    fn add_scalars(&mut self, input: &[Fp<C, N>]) -> ProofResult<()> {
        self.public_units(input)?;
        for i in input {
            i.serialize_compressed(&mut self.transcript)?;
        }
        Ok(())
    }
}

impl<G, H, R> GroupWriter<G> for Merlin<H, u8, R>
where
    G: CurveGroup,
    H: DuplexHash,
    R: RngCore + CryptoRng,
    Merlin<H, u8, R>: GroupPublic<G, Repr = Vec<u8>>,
{
    #[inline(always)]
    fn add_points(&mut self, input: &[G]) -> ProofResult<()> {
        let serialized = self.public_points(input);
        self.transcript.extend(serialized?);
        Ok(())
    }
}

impl<G, H, R, C: FpConfig<N>, C2: FpConfig<N>, const N: usize> GroupWriter<G>
    for Merlin<H, Fp<C, N>, R>
where
    G: CurveGroup<BaseField = Fp<C2, N>>,
    H: DuplexHash<Fp<C, N>>,
    R: RngCore + CryptoRng,
    Merlin<H, Fp<C, N>, R>: GroupPublic<G> + FieldWriter<G::BaseField>,
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
