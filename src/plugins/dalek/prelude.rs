pub use crate::{Arthur, DuplexHash, IOPattern, InvalidTag, Merlin};
use curve25519_dalek::{RistrettoPoint, Scalar};

pub trait DalekIO {
    fn absorb_scalars(self, count: usize, label: &'static str) -> Self;
    fn absorb_points(self, count: usize, label: &'static str) -> Self;
}

pub trait DalekBridge {
    fn absorb_scalars(&mut self, scalars: &[Scalar]) -> Result<(), InvalidTag>;
    fn absorb_points(&mut self, points: &[RistrettoPoint]) -> Result<(), InvalidTag>;
}
