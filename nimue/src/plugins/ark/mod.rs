//! This module contains utilities for working with [arkworks](https://arkworks.rs) types
//! and aid in the Fiat-Shamir heuristic for protocols dealing with
//! field elements and group elements.
//!
//! # Examples
//!
//! Here's a protocol that does Fiat-Shamir without caring about the hash function used
//! or the serialization format.
//!
//! ```rust
//! use ark_ec::CurveGroup;
//! use ark_std::UniformRand;
//! use nimue::{IOPattern, Merlin, DuplexHash, ProofResult};
//! use nimue::plugins::ark::*;
//!
//! fn prove<G: CurveGroup>(
//!     merlin: &mut Merlin,
//!     x: G::ScalarField,
//! ) -> ProofResult<&[u8]>
//! {
//!     let k = G::ScalarField::rand(merlin.rng());
//!     merlin.add_points(&[G::generator() * k])?;
//!     let [c]: [G::ScalarField; 1] = merlin.challenge_scalars()?;
//!     merlin.add_scalars(&[k + c * x])?;
//!     Ok(merlin.transcript())
//! }
//! ```
//! The type constraint on [`Merlin`][`crate::Merlin`] hints the compiler that we are going to be absorbing elements from the group `G` and squeezing challenges in the scalar field `G::ScalarField`. Similarly, we could have been squeezing out bytes.
//!
//! ```rust
//! # use ark_ec::CurveGroup;
//! # use ark_std::UniformRand;
//! # use ark_ff::PrimeField;
//! # use nimue::{IOPattern, Merlin, DuplexHash, ProofResult};
//! # use nimue::plugins::ark::*;
//!
//! fn prove<G: CurveGroup>(
//!     merlin: &mut Merlin,
//!     x: G::ScalarField,
//! ) -> ProofResult<&[u8]>
//! where
//!     Merlin: GroupWriter<G> + ByteChallenges,
//! {
//!     let k = G::ScalarField::rand(merlin.rng());
//!     merlin.add_points(&[G::generator() * k])?;
//!     let c_bytes = merlin.challenge_bytes::<16>()?;
//!     let c = G::ScalarField::from_le_bytes_mod_order(&c_bytes);
//!     merlin.add_scalars(&[k + c * x])?;
//!     Ok(merlin.transcript())
//! }
//! ```
//!
//! [`Merlin`][`crate::Merlin`] is actually more general than this, and can be used with any hash function, over any field.
//! Let's for instance use [`sha2`](https://crates.io/crates/sha2) on the above transcript instead of Keccak.
//!
//! ```rust
//! # use ark_ec::CurveGroup;
//! # use ark_std::UniformRand;
//! # use ark_ff::PrimeField;
//! # use nimue::{IOPattern, Merlin, DuplexHash, ProofResult};
//! # use nimue::plugins::ark::*;
//!
//! fn prove<G: CurveGroup, H: DuplexHash>(
//!     merlin: &mut Merlin<H>,
//!     x: G::ScalarField,
//! ) -> ProofResult<&[u8]>
//! # {
//! #     let k = G::ScalarField::rand(merlin.rng());
//! #     merlin.add_points(&[G::generator() * k])?;
//! #     let c_bytes = merlin.challenge_bytes::<16>()?;
//! #     let c = G::ScalarField::from_le_bytes_mod_order(&c_bytes);
//! #     merlin.add_scalars(&[k + c * x])?;
//! #     Ok(merlin.transcript())
//! # }
//! ```
//! No change to the function body is needed.
//! Now the proving function can be called with [`nimue::DigestBridge<sha2::Sha256>`][`crate::DigestBridge`].
//! As easy as that.
//! More _modern_ hash functions may want to operate over some some field different than $\mathbb{F}_8$,
//! for instance over the base field of the sponge.
//! Also in this case it's sufficient to slightly change the proving function to specify the field over which the
//! hash function operates, to something like:
//!
//! ```rust
//! # use ark_ec::CurveGroup;
//! # use ark_std::UniformRand;
//! # use ark_ff::{PrimeField, BigInteger};
//! # use nimue::{IOPattern, Merlin, DuplexHash, ProofResult};
//! # use nimue::plugins::ark::*;
//!
//! fn prove<G, H, U>(
//!     merlin: &mut Merlin<H, U>,
//!     x: G::ScalarField,
//! ) -> ProofResult<&[u8]>
//! where
//!     G: CurveGroup,
//!     G::BaseField: PrimeField,
//!     // Declares the type the hash function works on
//!     U: Unit,
//!     // Constrains the hash function to work over U, ...
//!     H: DuplexHash<U>,
//!     // ... and the prover to be able to absorb and squeeze elements from the group and the base field.
//!     // (normally would be the ScalarField but this is to make it work nicely with algebraic hashes)
//!     Merlin<H, U>: GroupWriter<G> + FieldWriter<G::BaseField> + ByteChallenges,
//! {
//!     let k = G::ScalarField::rand(merlin.rng());
//!     merlin.add_points(&[G::generator() * k])?;
//!     let c_bytes = merlin.challenge_bytes::<16>()?;
//!     let c = G::ScalarField::from_le_bytes_mod_order(&c_bytes);
//!     // XXX. very YOLO code, don't do this at home.
//!     // The resulting proof is malleable and could also not be correct if
//!     // G::BaseField::MODULUS < G::ScalarField::MODULUS
//!     let r = G::BaseField::from_le_bytes_mod_order(&(k + c * x).into_bigint().to_bytes_le());
//!     merlin.add_scalars(&[r])?;
//!     Ok(merlin.transcript())
//! }
//! ```
//! Now the above code should work with algebraic hashes such as `PoseidonHash` just as well as [`Keccak`][`crate::hash::Keccak`].
//!
/// Add public elements (field or group elements) to the protocol transcript.
mod common;
/// IO Pattern utilities.
mod iopattern;

/// Veririfer's utilities for decoding a transcript.
mod reader;
/// Prover's utilities for encoding into a transcript.
mod writer;

/// Tests for arkworks.
#[cfg(test)]
mod tests;

pub use crate::traits::*;
pub use crate::{hash::Unit, Arthur, DuplexHash, IOPattern, Merlin, ProofError, ProofResult, Safe};

super::traits::field_traits!(ark_ff::Field);
super::traits::group_traits!(ark_ec::CurveGroup, Scalar: ark_ff::PrimeField);

/// Move a value from prime field F1 to prime field F2.
///
/// Return an error if the element considered mod |F1| is different, when seen as an integer, mod |F2|.
/// This in particular happens when element > |F2|.
pub fn swap_field<F1: ark_ff::PrimeField, F2: ark_ff::PrimeField>(a_f1: F1) -> ProofResult<F2> {
    use ark_ff::BigInteger;
    let a_f2 = F2::from_le_bytes_mod_order(&a_f1.into_bigint().to_bytes_le());
    let a_f1_control = F1::from_le_bytes_mod_order(&a_f2.into_bigint().to_bytes_le());
    (a_f1 == a_f1_control)
        .then_some(a_f2)
        .ok_or(ProofError::SerializationError)
}

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

// impl<'a, P: ark_ec::pairing::Pairing, H, U> PairingWriter<P> for Arthur<'a, H, U> where
// U: Unit, H: DuplexHash<U>,
// Arthur<'a, H, U>:  GroupWriter<P::G1> + GroupWriter<P::G2>  {}
