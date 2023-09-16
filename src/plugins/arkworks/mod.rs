use crate::{errors::InvalidTag, hash::Unit, Arthur, DuplexHash, IOPattern, Merlin, Safe};

pub mod prelude;

// this module contains experiments for a more deep integration into arkworks.
// It doesn't work and is left here in this repository only for backlog.
// mod hazmat;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Fp, FpConfig, PrimeField, Field};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
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

impl<H: DuplexHash<U = u8>> Safe<H> {
    /// This function absorbs `count` object of size `S::default().compressed()`.
    /// It's not meant to be used publicly because it will not work properly for
    /// object whose size cannot be determined at compile time.
    fn absorb_serializable<S: CanonicalSerialize>(&mut self, input: &[S]) -> Result<(), InvalidTag> {
        let mut u8input = Vec::new();
        input
            .iter()
            .map(|s| s.serialize_compressed(&mut u8input))
            .collect::<Result<(), _>>()
            .map_err(|e| InvalidTag::from(e.to_string()))?;
        self.absorb(&u8input)
    }

    /// This function squeezes out a field element
    fn squeeze_pfelt<F: PrimeField>(&mut self) -> Result<F, InvalidTag> {
        let mut bytes = vec![0; f_bytes::<F>()];
        self.squeeze(&mut bytes)?;
        Ok(F::from_le_bytes_mod_order(&bytes))
    }

    pub fn squeeze_prime_fields<F: PrimeField>(&mut self, input: &[F]) -> Result<(), InvalidTag> {
        input.iter_mut().map(|i|
            self.squeeze_pfelt().map(|x| *i = x)
        ).collect()
    }

    pub fn absorb_points<G: CurveGroup>(&mut self, input: &[G]) -> Result<(), InvalidTag> {
        input
            .iter()
            .map(|i| match i.into_affine().xy() {
                // clone here is a hack for the API change
                // .xy() returning &(x, y) vs (x, y)
                Some((x, y)) => self.absorb_serializable(&[x.clone(), y.clone()]),
                None => unimplemented!(),
            })
            .collect()
    }

}


pub trait FieldSqueeze<F: Field>{
    fn squeeze_field(&mut self, output: &mut [F]) -> Result<(), InvalidTag>;
}

// impl<H, C: FpConfig<N>, const N: usize> FieldSqueeze<Fp<C, N>> for Safe<H> where H: DuplexHash<U = Fp<C, N>> {
//     fn squeeze_field(&mut self, output: &mut [Fp<C, N>]) -> Result<(), InvalidTag> {
//     Ok(())
//     }
// }
// impl<H, F: Field> FieldSqueeze<F> for Safe<H> where H: DuplexHash<U = u8> {
//     fn squeeze_field(&mut self, output: &mut [F]) -> Result<(), InvalidTag> {
//       let degree = F::extension_degree() as usize;
//       let mut buf = vec![F::BasePrimeField::default();  degree];
//       for mut o in output.iter_mut() {
//           self.squeeze_prime_fields(&mut buf)?;
//           // the slice is guaranteed to be the size of the extension degree
//           *o = F::from_base_prime_field_elems(&buf).unwrap();
//       }
//       Ok(())
//   }
//   }


// impl<H: DuplexHash> ArkIOPattern for IOPattern<H> {
//     /// This function will add `count` object of size `S::default().compressed()`.
//     ///
//     /// *WARNING* This way of estimating size is not accurate and is guaranteed to work
//     /// properly only for field and group elements. For example, it won't work properly for [`std::vec::Vec`].
//     fn absorb_serializable<S: Default + CanonicalSerialize>(
//         self,
//         count: usize,
//         label: &'static str,
//     ) -> Self {
//         self.absorb(count * S::default().compressed_size(), label)
//     }

//     fn squeeze_pfelt<F: PrimeField>(self, count: usize, label: &'static str) -> Self {
//         self.squeeze(count * f_bytes::<F>(), label)
//     }
// }
