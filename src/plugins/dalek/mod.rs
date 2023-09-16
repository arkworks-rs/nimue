pub mod prelude;

use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto, traits::Identity};
use prelude::*;

impl<H: DuplexHash> DalekIO for IOPattern<H> {
    fn absorb_scalars(self, count: usize, label: &'static str) -> Self {
        self.absorb(count * 32, label)
    }

    fn absorb_points(self, count: usize, label: &'static str) -> Self {
        self.absorb(count * 32, label)
    }
}

impl<'a, H: DuplexHash<U = u8>> prelude::DalekMerlin for Merlin<'a, H> {
    fn absorb_scalars<const N: usize>(&mut self) -> Result<[Scalar; N], InvalidTag> {
        let mut scalars = [Scalar::default(); N];
        let mut buf = [0u8; 32];
        for i in 0 .. N {
            self.absorb(&mut buf)?;
            scalars[i] = Scalar::from_canonical_bytes(buf).unwrap();
        }
        Ok(scalars)
    }

    fn absorb_points<const N: usize>(&mut self) -> Result<[RistrettoPoint; N], InvalidTag> {
        let mut points = [RistrettoPoint::identity(); N];
        let mut buf = [0u8; 32];
        for i in 0 .. N {
            self.absorb(&mut buf)?;
            points[i] = CompressedRistretto(buf).decompress().unwrap();
        }
        Ok(points)
    }
}
