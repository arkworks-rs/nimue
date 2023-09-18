use super::prelude::*;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Fp, FpConfig, PrimeField};
use ark_serialize::CanonicalSerialize;

impl<H: DuplexHash<u8>> Safe<H, u8> {
    /// This function absorbs `count` object of size `S::default().compressed()`.
    /// It's not meant to be used publicly because it will not work properly for
    /// object whose size cannot be determined at compile time.
    fn absorb_serializable<S: CanonicalSerialize>(
        &mut self,
        input: &[S],
    ) -> Result<(), InvalidTag> {
        let mut u8input = Vec::new();
        input
            .iter()
            .map(|s| s.serialize_compressed(&mut u8input))
            .collect::<Result<(), _>>()
            .map_err(|e| InvalidTag::from(e.to_string()))?;
        self.absorb(&u8input)
    }
}

impl<H, G> ArkSafe<G, u8> for Safe<H, u8>
where
    H: DuplexHash<u8>,
    G: CurveGroup,
    G::ScalarField: PrimeField,
{
    fn absorb_points(&mut self, input: &[G]) -> Result<(), InvalidTag> {
        input
            .iter()
            .map(|i| self.absorb_serializable(&[i.into_affine()]))
            .collect()
    }

    #[inline(always)]
    fn absorb_scalars(&mut self, input: &[G::ScalarField]) -> Result<(), InvalidTag> {
        self.absorb_serializable(input)
    }

    fn squeeze_scalars(&mut self, output: &mut [<G>::ScalarField]) -> Result<(), InvalidTag> {
        for o in output.iter_mut() {
            let mut buf = vec![0u8; super::f_bytes::<G::ScalarField>()];
            self.squeeze(&mut buf)?;
            *o = <G>::ScalarField::from_le_bytes_mod_order(&buf);
        }
        Ok(())
    }
}

impl<H, G, C, const N: usize> ArkSafe<G, Fp<C, N>> for Safe<H, G::BaseField>
where
    H: DuplexHash<Fp<C, N>>,
    G: CurveGroup<BaseField = Fp<C, N>>,
    C: FpConfig<N>,
{
    fn absorb_scalars(&mut self, _input: &[<G>::ScalarField]) -> Result<(), InvalidTag> {
        // what's the correct way to map a scalar eleemnt in the field?
        unimplemented!()
    }

    fn absorb_points(&mut self, input: &[G]) -> Result<(), InvalidTag> {
        input
            .iter()
            .map(|i| {
                self.absorb(
                    &i.into_affine()
                        .xy()
                        .map(|(x, y)| [x.clone(), y.clone()])
                        .expect("No points at infinity"),
                )
            })
            .collect()
    }

    fn squeeze_scalars(&mut self, _output: &mut [<G>::ScalarField]) -> Result<(), InvalidTag> {
        unimplemented!()
    }
}
