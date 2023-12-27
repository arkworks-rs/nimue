use std::ops::{Deref, DerefMut};

use crate::DefaultRng;
pub use crate::{hash::Unit, Arthur, DuplexHash, IOPattern, InvalidTag, Merlin, Safe};
use curve25519_dalek::{ristretto::RistrettoPoint, Scalar};

pub struct DalekIOPattern<H = crate::DefaultHash, U = u8>
where
    H: DuplexHash<U>,
    U: Unit,
{
    io: IOPattern<H, U>,
}

impl<H, U> Deref for DalekIOPattern<H, U>
where
    H: DuplexHash<U>,
    U: Unit,
{
    type Target = IOPattern<H, U>;

    fn deref(&self) -> &Self::Target {
        &self.io
    }
}

impl<H, U> From<IOPattern<H, U>> for DalekIOPattern<H, U>
where
    H: DuplexHash<U>,
    U: Unit,
{
    fn from(value: IOPattern<H, U>) -> Self {
        Self { io: value }
    }
}

impl<H: DuplexHash<u8>> DalekIOPattern<H, u8> {
    pub fn new(label: &str) -> Self {
        IOPattern::new(label).into()
    }

    pub fn ratchet(self) -> Self {
        self.io.ratchet().into()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.io.as_bytes()
    }

    pub fn add_scalars(self, count: usize, label: &str) -> Self {
        self.add_bytes(32 * count, label)
    }

    pub fn challenge_scalars(self, count: usize, label: &str) -> Self {
        self.challenge_bytes((32 + 16) * count, label)
    }

    pub fn add_bytes(self, count: usize, label: &str) -> Self {
        self.io.absorb(count, label).into()
    }

    pub fn challenge_bytes(self, count: usize, label: &str) -> Self {
        self.io.squeeze(count, label).into()
    }

    pub fn to_arthur(&self) -> DalekArthur<H> {
        DalekArthur::new(&self.io, DefaultRng::default())
    }
}

pub struct DalekArthur<H = crate::DefaultHash, R = rand::rngs::OsRng, U = u8>
where
    H: DuplexHash<U>,
    R: rand::RngCore + rand::CryptoRng,
    U: Unit,
{
    arthur: Arthur<H, R, U>,
}

impl<H, R, U> Deref for DalekArthur<H, R, U>
where
    H: DuplexHash<U>,
    R: rand::RngCore + rand::CryptoRng,
    U: Unit,
{
    type Target = Arthur<H, R, U>;

    fn deref(&self) -> &Self::Target {
        &self.arthur
    }
}

impl<H, R, U> DerefMut for DalekArthur<H, R, U>
where
    H: DuplexHash<U>,
    R: rand::RngCore + rand::CryptoRng,
    U: Unit,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.arthur
    }
}

impl<H, R, U> From<Arthur<H, R, U>> for DalekArthur<H, R, U>
where
    H: DuplexHash<U>,
    R: rand::RngCore + rand::CryptoRng,
    U: Unit,
{
    fn from(value: Arthur<H, R, U>) -> Self {
        Self { arthur: value }
    }
}

impl<H: DuplexHash<u8>, R: rand::RngCore + rand::CryptoRng> DalekArthur<H, R, u8> {
    pub fn new(io: &IOPattern<H, u8>, csrng: R) -> Self {
        Arthur::new(io, csrng).into()
    }

    pub fn public_scalars(&mut self, input: &[Scalar]) -> Result<Vec<u8>, InvalidTag> {
        let mut buf = Vec::new();

        for scalar in input {
            let bytes = &scalar.to_bytes();
            buf.extend(bytes);
        }

        self.add_bytes(&buf).map(|()| buf)
    }

    pub fn add_scalars(&mut self, input: &[Scalar]) -> Result<(), InvalidTag> {
        let serialized = self.public_scalars(input);
        self.arthur.transcript.extend(serialized?);
        Ok(())
    }

    pub fn fill_challenge_scalars(&mut self, output: &mut [Scalar]) -> Result<(), InvalidTag> {
        let mut buf = [[0u8; 32]; 2];

        for o in output.into_iter() {
            self.arthur.challenge_bytes(&mut buf[0])?;
            self.arthur.challenge_bytes(&mut buf[1][..16])?;
            *o = Scalar::from_bytes_mod_order(buf[0]) + Scalar::from_bytes_mod_order(buf[1]);
        }
        Ok(())
    }

    pub fn challenge_scalars<const N: usize>(&mut self) -> Result<[Scalar; N], InvalidTag> {
        let mut scalars = [Scalar::default(); N];
        self.fill_challenge_scalars(&mut scalars)?;
        Ok(scalars)
    }

    pub fn public_points(&mut self, input: &[RistrettoPoint]) -> Result<Vec<u8>, InvalidTag> {
        let mut buf = Vec::new();

        for point in input {
            let bytes = &point.compress().to_bytes();
            buf.extend(bytes);
        }

        self.arthur.add_bytes(&buf).map(|()| buf)
    }

    pub fn add_points(&mut self, input: &[RistrettoPoint]) -> Result<(), InvalidTag> {
        let serialized = self.public_points(input);
        self.arthur.transcript.extend(serialized?);
        Ok(())
    }



}

pub struct DalekMerlin<'a, H = crate::DefaultHash, U = u8>
where
    H: DuplexHash<U>,
    U: Unit,
{
    merlin: Merlin<'a, H, U>,
}

impl<'a, H, U> Deref for DalekMerlin<'a, H, U>
where
    H: DuplexHash<U>,
    U: Unit,
{
    type Target = Merlin<'a, H, U>;

    fn deref(&self) -> &Self::Target {
        &self.merlin
    }
}

impl<'a, H, U> DerefMut for DalekMerlin<'a, H, U>
where
    H: DuplexHash<U>,
    U: Unit,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.merlin
    }
}

impl<'a, H, U> From<Merlin<'a, H, U>> for DalekMerlin<'a, H, U>
where
    H: DuplexHash<U>,
    U: Unit,
{
    fn from(value: Merlin<'a, H, U>) -> Self {
        Self { merlin: value }
    }
}

impl<'a, H> DalekMerlin<'a, H, u8> where H: DuplexHash<u8> {}
