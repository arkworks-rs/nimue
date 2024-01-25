mod common;
mod iopattern;
mod reader;
mod writer;

pub use crate::traits::*;
pub use crate::{hash::Unit, Arthur, DuplexHash, IOPattern, IOPatternError, Merlin, Safe};
pub use iopattern::{ArkFieldIOPattern, ArkGroupIOPattern};

super::traits::field_traits!(ark_ff::Field);
super::traits::group_traits!(ark_ec::CurveGroup, G::Scalar : ark_ff::Field);
