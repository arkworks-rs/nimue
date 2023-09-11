pub use crate::{Arthur, DuplexHash, IOPattern, InvalidTag, Merlin};
use curve25519_dalek::{RistrettoPoint, Scalar};

pub trait DalekIO {
    fn absorb_scalars(self, count: usize, label: &'static str) -> Self;
    fn absorb_points(self, count: usize, label: &'static str) -> Self;
}

pub trait DalekMerlin {
    fn absorb_scalars<const N: usize>(&mut self) -> Result<[Scalar; N], InvalidTag>;
    fn absorb_points<const N: usize>(&mut self) -> Result<[RistrettoPoint; N], InvalidTag>;
}
