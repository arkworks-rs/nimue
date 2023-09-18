pub use crate::{hash::Unit, Arthur, DuplexHash, IOPattern, InvalidTag, Merlin, Safe};
use curve25519_dalek::{Scalar, ristretto::RistrettoPoint};

pub trait DalekIOPattern {
    fn absorb_points(self, count: usize, label: &'static str) -> Self;
    fn absorb_scalars(self, count: usize, label: &'static str) -> Self;
}

pub trait DalekSafe {
    fn absorb_scalars(&mut self, input: &[Scalar]) -> Result<(), InvalidTag>;
    fn absorb_ristretto(&mut self, input: &[RistrettoPoint]) -> Result<(), InvalidTag>;
}

pub trait DalekMerlin {
    fn absorb_scalars<const N: usize>(&mut self) -> Result<[Scalar; N], InvalidTag>;
    fn absorb_ristretto<const N: usize>(&mut self) -> Result<[RistrettoPoint; N], InvalidTag>;
}

pub trait DalekArthur {
    fn absorb_scalars(&mut self, input: &[Scalar]) -> Result<(), InvalidTag>;
    fn absorb_ristretto(&mut self, input: &[RistrettoPoint]) -> Result<(), InvalidTag>;
}