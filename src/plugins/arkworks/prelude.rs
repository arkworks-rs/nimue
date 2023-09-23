pub use super::iopattern::AlgebraicIOPattern;
pub use crate::{hash::Unit, Arthur, DuplexHash, IOPattern, InvalidTag, Merlin, Safe};
use ark_ec::CurveGroup;

pub trait ArkIOPattern<G: CurveGroup, U: Unit> {
    fn absorb_scalars(self, count: usize, label: &str) -> Self;
    fn absorb_points(self, count: usize, label: &str) -> Self;
    fn squeeze_scalars(self, count: usize, label: &str) -> Self;
}

pub trait ArkSafe<G: CurveGroup, U: Unit> {
    fn absorb_scalars(&mut self, input: &[G::ScalarField]) -> Result<(), InvalidTag>;
    fn absorb_points(&mut self, input: &[G]) -> Result<(), InvalidTag>;
    fn squeeze_scalars(&mut self, output: &mut [G::ScalarField]) -> Result<(), InvalidTag>;
}

pub trait ArkMerlin<G: CurveGroup, U: Unit> {
    fn absorb_scalars<const N: usize>(&mut self) -> Result<[G::ScalarField; N], InvalidTag>;
    fn absorb_points<const N: usize>(&mut self) -> Result<[G; N], InvalidTag>;

    fn public_points(&mut self, input: &[G]) -> Result<(), InvalidTag>;
    fn public_scalars(&mut self, input: &[G::ScalarField]) -> Result<(), InvalidTag>;

    fn squeeze_scalars<const N: usize>(&mut self) -> Result<[G::ScalarField; N], InvalidTag>;
}

pub trait ArkArthur<G: CurveGroup, U: Unit> {
    fn absorb_scalars(&mut self, input: &[G::ScalarField]) -> Result<(), InvalidTag>;
    fn absorb_points(&mut self, input: &[G]) -> Result<(), InvalidTag>;

    fn public_points(&mut self, input: &[G]) -> Result<(), InvalidTag>;
    fn public_scalars(&mut self, input: &[G::ScalarField]) -> Result<(), InvalidTag>;

    fn squeeze_scalars<const N: usize>(&mut self) -> Result<[G::ScalarField; N], InvalidTag>;
}
