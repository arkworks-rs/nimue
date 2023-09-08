use crate::{errors::InvalidTag, hash::Unit, Arthur, DuplexHash, IOPattern, Merlin};

pub mod prelude;

// this module contains experiments for a more deep integration into arkworks.
// It doesn't work and is left here in this repository only for backlog.
// mod hazmat;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Fp, FpConfig, PrimeField};
use ark_serialize::CanonicalSerialize;
use prelude::*;
use rand::{CryptoRng, RngCore};

impl<C: FpConfig<N>, const N: usize> Unit for Fp<C, N> {
    fn write(bunch: &[Self], w: &mut impl std::io::Write) -> Result<(), std::io::Error> {
        bunch
            .serialize_compressed(w)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "oh no!"))
    }
}

impl<H: DuplexHash<U = u8>> Bridgeu8 for Merlin<H, u8> {
    fn absorb_serializable<S: CanonicalSerialize>(&mut self, input: &[S]) -> Result<(), SerTagErr> {
        let mut u8input = Vec::new();
        input
            .iter()
            .map(|s| s.serialize_compressed(&mut u8input))
            .collect::<Result<(), _>>()
            .map_err(|e| SerTagErr::Ser(e))?;
        self.absorb_native(&u8input).map_err(|e| SerTagErr::Tag(e))
    }

    fn squeeze_pfelt<F: PrimeField>(&mut self) -> Result<F, InvalidTag> {
        let len = ((F::BasePrimeField::MODULUS_BIT_SIZE + 128) / 8) as usize;
        let mut bytes = vec![0; len];
        self.squeeze_bytes(&mut bytes)?;
        Ok(F::from_le_bytes_mod_order(&bytes))
    }
}

impl<H: DuplexHash<U = u8>, R: RngCore + CryptoRng> Bridgeu8 for Arthur<H, R, u8> {
    fn absorb_serializable<S: CanonicalSerialize>(&mut self, input: &[S]) -> Result<(), SerTagErr> {
        let mut u8input = Vec::new();
        input
            .iter()
            .map(|s| s.serialize_compressed(&mut u8input))
            .collect::<Result<(), _>>()
            .map_err(|e| SerTagErr::Ser(e))?;
        self.absorb_native(&u8input).map_err(|e| SerTagErr::Tag(e))
    }

    fn squeeze_pfelt<F: PrimeField>(&mut self) -> Result<F, InvalidTag> {
        self.merlin.squeeze_pfelt()
    }
}

impl<C: FpConfig<N>, const N: usize, H: DuplexHash<U = Fp<C, N>>> BridgeField
    for Merlin<H, Fp<C, N>>
{
    type U = Fp<C, N>;

    fn absorb_scalars(&mut self, input: &[Self::U]) -> Result<(), InvalidTag> {
        self.absorb_native(input)
    }

    fn absorb_points<G>(&mut self, input: &[G]) -> Result<(), InvalidTag>
    where
        G: CurveGroup<BaseField = Self::U>,
    {
        input
            .iter()
            .map(|i| match i.into_affine().xy() {
                // clone here is a hack for the API change
                // .xy() returning &(x, y) vs (x, y)
                Some((x, y)) => self.absorb_native(&[x.clone(), y.clone()]),
                None => unimplemented!(),
            })
            .collect()
    }

    fn squeeze_scalars(&mut self, output: &mut [Self::U]) -> Result<(), InvalidTag> {
        self.squeeze_native(output)
    }
}

impl<H: DuplexHash> ArkIOPattern for IOPattern<H> {
    /// This function will add `count` object of size `S::default().compressed()`.
    ///
    /// *WARNING* This way of estimating size is not accurate and is guaranteed to work
    /// properly only for field and group elements. For example, it won't work properly for [`std::vec::Vec`].
    fn absorb_serializable<S: Default + CanonicalSerialize>(
        self,
        count: usize,
        label: &'static str,
    ) -> Self {
        self.absorb(count * S::default().compressed_size(), label)
    }

    fn squeeze_pfelt<F: PrimeField>(self, count: usize, label: &'static str) -> Self {
        self.absorb(count * (F::MODULUS_BIT_SIZE as usize + 128) / 8, label)
    }
}
