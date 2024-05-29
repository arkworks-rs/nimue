use ark_ec::short_weierstrass::{Affine as SWAffine, Projective as SWCurve, SWCurveConfig};
use ark_ec::twisted_edwards::{Affine as EdwardsAffine, Projective as EdwardsCurve, TECurveConfig};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::{Fp, FpConfig};
use ark_serialize::CanonicalDeserialize;

use super::{FieldReader, GroupReader};
use crate::traits::*;
use crate::{Arthur, DuplexHash, ProofResult};

impl<'a, F, H> FieldReader<F> for Arthur<'a, H>
where
    F: Field,
    H: DuplexHash,
{
    fn fill_next_scalars(&mut self, output: &mut [F]) -> ProofResult<()> {
        let point_size = F::default().compressed_size();
        let mut buf = vec![0u8; point_size];
        for o in output.iter_mut() {
            self.fill_next_bytes(&mut buf)?;
            *o = F::deserialize_compressed(buf.as_slice())?;
        }
        Ok(())
    }
}

impl<'a, G, H> GroupReader<G> for Arthur<'a, H>
where
    G: CurveGroup,
    H: DuplexHash,
{
    fn fill_next_points(&mut self, output: &mut [G]) -> ProofResult<()> {
        let point_size = G::default().compressed_size();
        let mut buf = vec![0u8; point_size];

        for o in output.iter_mut() {
            self.fill_next_units(&mut buf)?;
            *o = G::deserialize_compressed(buf.as_slice())?;
        }
        Ok(())
    }
}

impl<'a, H, C, const N: usize> FieldReader<Fp<C, N>> for Arthur<'a, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexHash<Fp<C, N>>,
{
    fn fill_next_scalars(&mut self, output: &mut [Fp<C, N>]) -> crate::ProofResult<()> {
        self.fill_next_units(output)?;
        Ok(())
    }
}

impl<'a, P, H, C, const N: usize> GroupReader<EdwardsCurve<P>> for Arthur<'a, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexHash<Fp<C, N>>,
    P: TECurveConfig<BaseField = Fp<C, N>>,
{
    fn fill_next_points(&mut self, output: &mut [EdwardsCurve<P>]) -> ProofResult<()> {
        for o in output.iter_mut() {
            let o_affine = EdwardsAffine::deserialize_compressed(&mut self.transcript)?;
            *o = o_affine.into();
            self.public_units(&[o.x, o.y])?;
        }
        Ok(())
    }
}

impl<'a, P, H, C, const N: usize> GroupReader<SWCurve<P>> for Arthur<'a, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexHash<Fp<C, N>>,
    P: SWCurveConfig<BaseField = Fp<C, N>>,
{
    fn fill_next_points(&mut self, output: &mut [SWCurve<P>]) -> ProofResult<()> {
        for o in output.iter_mut() {
            let o_affine = SWAffine::deserialize_compressed(&mut self.transcript)?;
            *o = o_affine.into();
            self.public_units(&[o.x, o.y])?;
        }
        Ok(())
    }
}
