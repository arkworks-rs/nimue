use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use prelude::*;
use rand::{CryptoRng, RngCore};

pub mod prelude;

use crate::{Arthur, DuplexHash, IOPattern, InvalidTag, Merlin, Safe};

impl<H: DuplexHash<u8>> DalekIOPattern for IOPattern<H, u8> {
    fn add_scalars(self, count: usize, label: &'static str) -> Self {
        self.absorb(count * 32, label)
    }

    fn add_ristretto(self, count: usize, label: &'static str) -> Self {
        self.absorb(count * 32, label)
    }
}

impl<H: DuplexHash<u8>> Safe<H, u8> {
    pub fn add_scalars(&mut self, input: &[Scalar]) -> Result<(), InvalidTag> {
        for scalar in input {
            self.absorb(&scalar.to_bytes())?;
        }
        Ok(())
    }

    pub fn add_ristretto(&mut self, input: &[RistrettoPoint]) -> Result<(), InvalidTag> {
        for point in input {
            self.absorb(&point.compress().to_bytes())?;
        }
        Ok(())
    }
}

impl<'a, H: DuplexHash<u8>> DalekMerlin for Merlin<'a, H, u8> {
    fn add_scalars<const N: usize>(&mut self) -> Result<[Scalar; N], InvalidTag> {
        let mut scalars = [Scalar::default(); N];
        let mut buf = [0u8; 32];
        for i in 0..N {
            self.fill_next(&mut buf)?;
            scalars[i] = Scalar::from_canonical_bytes(buf).unwrap();
        }
        Ok(scalars)
    }

    fn add_ristretto<const N: usize>(&mut self) -> Result<[RistrettoPoint; N], InvalidTag> {
        let mut points = [RistrettoPoint::default(); N];
        let mut buf = [0u8; 32];
        for i in 0..N {
            self.fill_next(&mut buf)?;
            points[i] = CompressedRistretto(buf).decompress().unwrap();
        }
        Ok(points)
    }
}

impl<H: DuplexHash<u8>, R: RngCore + CryptoRng> DalekArthur for Arthur<H, R, u8> {
    fn add_scalars(&mut self, input: &[Scalar]) -> Result<(), InvalidTag> {
        for scalar in input {
            let bytes = &scalar.to_bytes();
            self.transcript.extend(bytes);
            self.add(bytes)?;
        }
        Ok(())
    }

    fn add_ristretto(&mut self, input: &[RistrettoPoint]) -> Result<(), InvalidTag> {
        for point in input {
            let bytes = &point.compress().to_bytes();
            self.transcript.extend(bytes);
            self.add(bytes)?;
        }
        Ok(())
    }
}
