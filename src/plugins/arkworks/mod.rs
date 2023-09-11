use crate::{errors::InvalidTag, hash::Unit, Arthur, DuplexHash, IOPattern, Merlin, Safe};

pub mod prelude;

// this module contains experiments for a more deep integration into arkworks.
// It doesn't work and is left here in this repository only for backlog.
// mod hazmat;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Fp, FpConfig, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use prelude::*;
use rand::{CryptoRng, RngCore};
use std::io;

const fn f_bytes<F: PrimeField>() -> usize {
    (F::MODULUS_BIT_SIZE as usize + 128) / 8
}

impl<C: FpConfig<N>, const N: usize> Unit for Fp<C, N> {
    fn write(bunch: &[Self], w: &mut impl io::Write) -> Result<(), io::Error> {
        bunch
            .iter()
            .map(|b| {
                b.serialize_compressed(w)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "oh no!"))
            })
            .collect()
    }

    fn read(r: &mut impl std::io::Read, bunch: &mut [Self]) -> Result<(), std::io::Error> {
        for b in bunch.iter_mut() {
            *b = ark_ff::Fp::<C, N>::deserialize_compressed(r)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "oh no!"))?
        }
        Ok(())
    }
}

impl<H: DuplexHash<U = u8>> Bridgeu8 for Safe<H> {
    fn absorb_serializable<S: CanonicalSerialize>(&mut self, input: &[S]) -> Result<(), SerTagErr> {
        let mut u8input = Vec::new();
        input
            .iter()
            .map(|s| s.serialize_compressed(&mut u8input))
            .collect::<Result<(), _>>()
            .map_err(|e| SerTagErr::Ser(e))?;
        self.absorb(&u8input).map_err(|e| SerTagErr::Tag(e))
    }

    fn squeeze_pfelt<F: PrimeField>(&mut self) -> Result<F, InvalidTag> {
        let mut bytes = vec![0; f_bytes::<F>()];
        self.squeeze(&mut bytes)?;
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
        match self.absorb(&u8input) {
            Err(e) => Err(SerTagErr::Tag(e)),
            Ok(()) => Ok(()),
        }
    }

    fn squeeze_pfelt<F: PrimeField>(&mut self) -> Result<F, InvalidTag> {
        self.safe.squeeze_pfelt()
    }
}

impl<C: FpConfig<N>, const N: usize, H: DuplexHash<U = Fp<C, N>>> BridgeField
    for Merlin<H, Fp<C, N>>
{
    type U = Fp<C, N>;

    fn read_scalars<const Len: usize>(&mut self) -> Result<[Self::U; Len], InvalidTag> {
        let mut input = [Self::U::default(); Len];
        self.absorb(&mut input).map(|()| input)
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
                Some((x, y)) => self.absorb(&[x.clone(), y.clone()]),
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
        println!("IO: {} * {}", f_bytes::<F>(), count);
        self.squeeze(count * f_bytes::<F>(), label)
    }
}
