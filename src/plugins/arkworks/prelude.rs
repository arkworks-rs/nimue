use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalSerialize, SerializationError};
use core::fmt::{Display, Formatter, Debug};

use crate::{hash::Unit, InvalidTag};

#[derive(Debug)]
pub enum SerTagErr {
    Ser(SerializationError),
    Tag(InvalidTag),
}

pub trait ArkIOPattern {
    fn absorb_serializable<S: Default + CanonicalSerialize>(
        self,
        count: usize,
        label: &'static str,
    ) -> Self;

    fn squeeze_pfelt<F: PrimeField>(self, count: usize, label: &'static str) -> Self;

}

impl Display for SerTagErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SerTagErr::Tag(e) => Debug::fmt(e, f),
            SerTagErr::Ser(e) => Display::fmt(e, f),
        }
    }
}

pub trait BridgeField {
    type U: Unit + Field;
    fn absorb_scalars(&mut self, input: &[Self::U]) -> Result<(), InvalidTag>;
    fn absorb_points<G>(&mut self, input: &[G]) -> Result<(), InvalidTag>
    where
        G: CurveGroup<BaseField = Self::U>;

    fn squeeze_scalars(&mut self, output: &mut [Self::U]) -> Result<(), InvalidTag>;
}

pub trait Bridgeu8 {
    fn absorb_serializable<S: CanonicalSerialize>(&mut self, input: &[S]) -> Result<(), SerTagErr>;
    fn squeeze_pfelt<F: PrimeField>(&mut self) -> Result<F, InvalidTag>;
}
