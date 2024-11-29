use ark_ec::CurveGroup;
use ark_ff::{Field, Fp, FpConfig};
use ark_serialize::CanonicalSerialize;
use rand::{CryptoRng, RngCore};

use super::{FieldPublic, FieldWriter, GroupPublic, GroupWriter};
use crate::{
    Arthur, BytePublic, ByteReader, ByteWriter, DuplexHash, IOPatternError, Merlin, ProofResult,
    Unit, UnitTranscript,
};

impl<F: Field, H: DuplexHash, R: RngCore + CryptoRng> FieldWriter<F> for Merlin<H, u8, R> {
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

impl<H, R, C, const N: usize> ByteWriter for Merlin<H, Fp<C, N>, R>
where
    H: DuplexHash<Fp<C, N>>,
    C: FpConfig<N>,
    R: RngCore + CryptoRng,
{
    fn add_bytes(&mut self, input: &[u8]) -> Result<(), IOPatternError> {
        self.public_bytes(input)?;
        self.transcript.extend(input);
        Ok(())
    }
}

impl<H, C, const N: usize> ByteReader for Arthur<'_, H, Fp<C, N>>
where
    H: DuplexHash<Fp<C, N>>,
    C: FpConfig<N>,
{
    fn fill_next_bytes(&mut self, input: &mut [u8]) -> Result<(), IOPatternError> {
        u8::read(&mut self.transcript, input)?;
        self.public_bytes(input)
    }
}
