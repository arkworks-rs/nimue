pub mod prelude;

use curve25519_dalek::{RistrettoPoint, Scalar};
use prelude::*;

impl<H: DuplexHash> DalekIO for IOPattern<H> {
    fn absorb_scalars(self, count: usize, label: &'static str) -> Self {
        self.absorb(count * 32, label)
    }

    fn absorb_points(self, count: usize, label: &'static str) -> Self {
        self.absorb(count * 32, label)
    }
}

impl<'a, H: DuplexHash<U = u8>> prelude::DalekMerlin for Merlin<'a, H, u8> {
    fn absorb_scalars<const N: usize>(&mut self) -> Result<[Scalar; N], InvalidTag> {
        let mut scalars = [Scalar::default(); N];
        let buf = [0u8; 32];
        for i in 0 .. N {
            self.absorb(&mut buf);
            scalars[i] = Scalar::from_canonical_bytes(buf);
        }

        self.absorb(&mut buf)?;


            scalars.iter().map(|s| self.absorb(s.as_bytes())).collect()
    }

    fn absorb_points(&mut self, points: &[RistrettoPoint]) -> Result<(), InvalidTag> {
        points
            .iter()
            .map(|p| self.absorb(p.compress().as_bytes()))
            .collect()
    }
}
