use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use rand::CryptoRng;

use super::prelude::*;

pub struct ArkFieldArthur<F: Field, H = crate::DefaultHash, U = u8, R = crate::DefaultRng>
where
    H: DuplexHash<U>,
    U: Unit,
    R: rand::RngCore + CryptoRng,
{
    arthur: Arthur<H, R, U>,
    _base: std::marker::PhantomData<F>,
}

impl<F, R, H, U> core::ops::Deref for ArkFieldArthur<F, H, U, R>
where
    H: DuplexHash<U>,
    U: Unit,
    R: rand::RngCore + CryptoRng,
    F: Field,
{
    type Target = Arthur<H, R, U>;

    fn deref(&self) -> &Self::Target {
        &self.arthur
    }
}

impl<F, R, H, U> core::ops::DerefMut for ArkFieldArthur<F, H, U, R>
where
    H: DuplexHash<U>,
    U: Unit,
    R: rand::RngCore + CryptoRng,
    F: Field,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.arthur
    }
}

impl<F, R, H, U> From<Arthur<H, R, U>> for ArkFieldArthur<F, H, U, R>
where
    F: Field,
    H: DuplexHash<U>,
    U: Unit,
    R: rand::RngCore + CryptoRng,
{
    fn from(value: Arthur<H, R, U>) -> Self {
        Self {
            arthur: value,
            _base: std::marker::PhantomData::default(),
        }
    }
}

impl<F, R, H> ArkFieldArthur<F, H, u8, R>
where
    F: PrimeField,
    H: DuplexHash<u8>,
    R: rand::RngCore + CryptoRng,
{
    pub fn new(io: &IOPattern<H, u8>, csrng: R) -> Self {
        Arthur::new(io, csrng).into()
    }

    pub fn public_scalars(&mut self, input: &[F]) -> Result<Vec<u8>, InvalidTag> {
        let mut buf = Vec::<u8>::new();

        for scalar in input {
            scalar
                .serialize_compressed(&mut buf)
                .expect("serialization failed");
        }
        self.absorb(&buf).map(|()| buf)
    }

    fn absorb_scalars(&mut self, input: &[F]) -> Result<(), InvalidTag> {
        let serialized = self.public_scalars(input)?;
        self.arthur.transcript.extend(serialized);
        Ok(())
    }

    fn squeeze_scalars_fill(&mut self, output: &mut [F]) -> Result<(), InvalidTag> {
        let mut buf = vec![0u8; super::f_bytes::<F>()];
        for o in output.iter_mut() {
            self.arthur.squeeze(&mut buf)?;
            *o = F::from_le_bytes_mod_order(&buf);
        }
        Ok(())
    }

    fn squeeze_scalars<const N: usize>(&mut self) -> Result<[F; N], InvalidTag> {
        let mut output = [F::default(); N];
        self.squeeze_scalars_fill(&mut output)?;
        Ok(output)
    }
}

pub struct ArkGroupArthur<G, H = crate::DefaultHash, U = u8, R = crate::DefaultRng>
where
    G: CurveGroup,
    H: DuplexHash<U>,
    U: Unit,
    R: rand::RngCore + CryptoRng,
{
    arthur: ArkFieldArthur<G::ScalarField, H, U, R>,
    _base: std::marker::PhantomData<G>,
}

impl<G, R, H, U> From<Arthur<H, R, U>> for ArkGroupArthur<G, H, U, R>
where
    G: CurveGroup,
    H: DuplexHash<U>,
    R: rand::RngCore + CryptoRng,
    U: Unit,
{
    fn from(value: Arthur<H, R, U>) -> Self {
        Self {
            arthur: value.into(),
            _base: Default::default(),
        }
    }
}

impl<G, R, H, U> core::ops::Deref for ArkGroupArthur<G, H, U, R>
where
    G: CurveGroup,
    H: DuplexHash<U>,
    R: rand::RngCore + CryptoRng,
    U: Unit,
{
    type Target = Arthur<H, R, U>;

    fn deref(&self) -> &Self::Target {
        self.arthur.deref()
    }
}

impl<G, R, H, U> core::ops::DerefMut for ArkGroupArthur<G, H, U, R>
where
    G: CurveGroup,
    H: DuplexHash<U>,
    R: rand::RngCore + CryptoRng,
    U: Unit,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.arthur.deref_mut()
    }
}

impl<G, H, R> ArkGroupArthur<G, H, u8, R>
where
    G: CurveGroup,
    H: DuplexHash<u8>,
    R: rand::RngCore + CryptoRng,
{
    pub fn new(io: &IOPattern<H, u8>, csrng: R) -> Self {
        Arthur::new(io, csrng).into()
    }

    pub fn public_scalars(&mut self, input: &[G::ScalarField]) -> Result<Vec<u8>, InvalidTag> {
        self.arthur.public_scalars(input)
    }

    pub fn absorb_scalars(&mut self, input: &[G::ScalarField]) -> Result<(), InvalidTag> {
        self.arthur.absorb_scalars(input)
    }

    pub fn squeeze_scalars_fill(
        &mut self,
        output: &mut [G::ScalarField],
    ) -> Result<(), InvalidTag> {
        self.arthur.squeeze_scalars_fill(output)
    }

    pub fn squeeze_scalars<const N: usize>(&mut self) -> Result<[G::ScalarField; N], InvalidTag> {
        self.arthur.squeeze_scalars()
    }

    pub fn public_points(&mut self, input: &[G]) -> Result<Vec<u8>, InvalidTag> {
        let mut buf = Vec::<u8>::new();
        for point in input {
            point
                .serialize_compressed(&mut buf)
                .expect("serialization failed");
        }
        self.arthur.absorb(&buf).map(|()| buf)
    }

    pub fn absorb_points(&mut self, input: &[G]) -> Result<(), InvalidTag> {
        let serialized = self.public_points(input)?;
        self.arthur.transcript.extend(serialized);
        Ok(())
    }
}

// impl<H, G, R> ArkGGArthur<G, u8> for Arthur<H, R, u8>
// where
//     H: DuplexHash<u8>,
//     G: CurveGroup,
//     R: RngCore + CryptoRng,
//     Arthur<H, R, u8>: ArkFFArthur<G::ScalarField, u8>,
// {
//     // fn absorb_scalars(&mut self, input: &[G::ScalarField]) -> Result<(), InvalidTag> {
//     //     <Arthur<H, R> as ArkFFArthur<G::ScalarField, u8>>::absorb_scalars(self, input)
//     // }

//     fn public_points(&mut self, input: &[G]) -> Result<(), InvalidTag> {
//         let len = self.transcript.len();
//         self.absorb_points(input)?;
//         self.transcript.truncate(len);
//         Ok(())
//     }

//     // fn public_scalars(&mut self, input: &[G::ScalarField]) -> Result<(), InvalidTag> {
//     //     <Arthur<H, R> as ArkFFArthur<G::ScalarField, u8>>::public_scalars(self, input)
//     // }

//     fn absorb_points(&mut self, input: &[G]) -> Result<(), InvalidTag> {

//     }

//     // fn squeeze_scalars<const N: usize>(&mut self) -> Result<[G::ScalarField; N], InvalidTag> {
//     //     <Arthur<H, R> as ArkFFArthur<G::ScalarField, u8>>::squeeze_scalars(self)
//     // }
// }
