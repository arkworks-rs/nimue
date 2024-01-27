mod common;
mod iopattern;
mod reader;
mod writer;
// poseidon support
pub mod poseidon;

pub use crate::traits::*;
pub use crate::{hash::Unit, Arthur, DuplexHash, IOPattern, Merlin, ProofError, ProofResult, Safe};

super::traits::field_traits!(ark_ff::PrimeField);
super::traits::group_traits!(ark_ec::CurveGroup, G::Scalar : ark_ff::Field);

// pub trait PairingReader<P: ark_ec::pairing::Pairing>: GroupReader<P::G1> + GroupReader<P::G2>  {
//     fn fill_next_g1_points(&mut self, input: &mut [P::G1]) -> crate::ProofResult<()> {
//         GroupReader::<P::G1>::fill_next_points(self, input)
//     }

//     fn fill_next_g2_points(&mut self, input: &mut [P::G2]) -> crate::ProofResult<()> {
//         GroupReader::<P::G2>::fill_next_points(self, input)
//     }
// }
// pub trait PairingWriter<P: ark_ec::pairing::Pairing> {
//     fn add_g1_points(&mut self, input: &[P::G1]) -> crate::ProofResult<()> {
//         GroupWriter::<P::G1>::add_points(self, input)
//     }

//     fn add_g2_points(&mut self, input: &[P::G2]) -> crate::ProofResult<()> {
//         GroupWriter::<P::G2>::add_points(self, input)
//     }
// }

// impl<'a, P: ark_ec::pairing::Pairing, H, U> PairingWriter<P> for Merlin<'a, H, U> where
// U: Unit, H: DuplexHash<U>,
// Merlin<'a, H, U>:  GroupWriter<P::G1> + GroupWriter<P::G2>  {}
