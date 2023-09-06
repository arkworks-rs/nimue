mod prelude;

use curve25519_dalek::{RistrettoPoint, Scalar};

use crate::{DuplexHash, IOPattern, InvalidTag, Merlin};

impl prelude::DalekIO for IOPattern {
    fn absorb_scalars(self, count: usize, label: &'static str) -> Self {
        self.absorb(count * 32, label)
    }

    fn absorb_points(self, count: usize, label: &'static str) -> Self {
        self.absorb(count * 32, label)
    }
}

impl<H: DuplexHash<U = u8>> prelude::DalekBridge for Merlin<H> {
    fn absorb_scalars(&mut self, scalars: &[Scalar]) -> Result<(), InvalidTag> {
        scalars
            .iter()
            .map(|s| self.absorb_native(s.as_bytes()))
            .collect()
    }

    fn absorb_points(&mut self, points: &[RistrettoPoint]) -> Result<(), InvalidTag> {
        points
            .iter()
            .map(|p| self.absorb_native(p.compress().as_bytes()))
            .collect()
    }
}
