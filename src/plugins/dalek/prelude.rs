pub use crate::{hash::Unit, Arthur, DuplexHash, IOPattern, InvalidTag, Merlin, Safe};
use curve25519_dalek::{ristretto::RistrettoPoint, Scalar};

pub trait DalekIOPattern {
    fn add_ristretto(self, count: usize, label: &'static str) -> Self;
    fn add_scalars(self, count: usize, label: &'static str) -> Self;
}

pub trait DalekSafe {
    fn absorb_scalars(&mut self, input: &[Scalar]) -> Result<(), InvalidTag>;
    fn absorb_ristretto(&mut self, input: &[RistrettoPoint]) -> Result<(), InvalidTag>;
}

pub trait DalekMerlin {
    fn add_scalars<const N: usize>(&mut self) -> Result<[Scalar; N], InvalidTag>;
    fn add_ristretto<const N: usize>(&mut self) -> Result<[RistrettoPoint; N], InvalidTag>;
}

pub trait DalekArthur {
    fn add_scalars(&mut self, input: &[Scalar]) -> Result<(), InvalidTag>;
    fn add_ristretto(&mut self, input: &[RistrettoPoint]) -> Result<(), InvalidTag>;
}
