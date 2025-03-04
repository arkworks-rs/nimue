use ark_ec::CurveGroup;
use ark_ff::{Field, Fp, FpConfig};
use ark_serialize::CanonicalSerialize;
use rand::{CryptoRng, RngCore};

use super::{CommonProverMessageField, ProverMessageField, CommonProverMessageGroup, ProverMessageGroup};
use crate::{
    CommonProverMessageBytes, ByteReader, ByteWriter, DuplexInterface, DomainSeparatorMismatch, ProofResult,
    ProverState, Unit, UnitTranscript, VerifierState,
};

impl<F: Field, H: DuplexInterface, R: RngCore + CryptoRng> ProverMessageField<F>
    for ProverState<H, u8, R>
{
    fn add_scalars(&mut self, input: &[F]) -> ProofResult<()> {
        let serialized = self.public_scalars(input);
        self.narg_string.extend(serialized?);
        Ok(())
    }
}

impl<C: FpConfig<N>, H: DuplexInterface<Fp<C, N>>, R: RngCore + CryptoRng, const N: usize>
    ProverMessageField<Fp<C, N>> for ProverState<H, Fp<C, N>, R>
{
    fn add_scalars(&mut self, input: &[Fp<C, N>]) -> ProofResult<()> {
        self.public_units(input)?;
        for i in input {
            i.serialize_compressed(&mut self.narg_string)?;
        }
        Ok(())
    }
}

impl<G, H, R> ProverMessageGroup<G> for ProverState<H, u8, R>
where
    G: CurveGroup,
    H: DuplexInterface,
    R: RngCore + CryptoRng,
    ProverState<H, u8, R>: CommonProverMessageGroup<G, Repr = Vec<u8>>,
{
    #[inline(always)]
    fn add_points(&mut self, input: &[G]) -> ProofResult<()> {
        let serialized = self.public_points(input);
        self.narg_string.extend(serialized?);
        Ok(())
    }
}

impl<G, H, R, C: FpConfig<N>, C2: FpConfig<N>, const N: usize> ProverMessageGroup<G>
    for ProverState<H, Fp<C, N>, R>
where
    G: CurveGroup<BaseField = Fp<C2, N>>,
    H: DuplexInterface<Fp<C, N>>,
    R: RngCore + CryptoRng,
    ProverState<H, Fp<C, N>, R>: CommonProverMessageGroup<G> + ProverMessageField<G::BaseField>,
{
    #[inline(always)]
    fn add_points(&mut self, input: &[G]) -> ProofResult<()> {
        self.public_points(input).map(|_| ())?;
        for i in input {
            i.serialize_compressed(&mut self.narg_string)?;
        }
        Ok(())
    }
}

impl<H, R, C, const N: usize> ByteWriter for ProverState<H, Fp<C, N>, R>
where
    H: DuplexInterface<Fp<C, N>>,
    C: FpConfig<N>,
    R: RngCore + CryptoRng,
{
    fn add_bytes(&mut self, input: &[u8]) -> Result<(), DomainSeparatorMismatch> {
        self.public_bytes(input)?;
        self.narg_string.extend(input);
        Ok(())
    }
}

impl<H, C, const N: usize> ByteReader for VerifierState<'_, H, Fp<C, N>>
where
    H: DuplexInterface<Fp<C, N>>,
    C: FpConfig<N>,
{
    fn fill_next_bytes(&mut self, input: &mut [u8]) -> Result<(), DomainSeparatorMismatch> {
        u8::read(&mut self.transcript, input)?;
        self.public_bytes(input)
    }
}
