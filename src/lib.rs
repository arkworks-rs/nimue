#![feature(int_roundings)]
//!
//! **This is work in progress, not suitable for production.**
//!
//! This library is a secure construction for zero-knowledge proofs based on [SAFE].
//! It enables secure provision of randomness for the prover and secure generation
//! of random coins for the verifier.
//!
//! This allows for the implementation of non-interactive protocols in a readable manner,
//! in a unified framework for sponge functions.
//!
//! # Features
//!
//! This library is inspired by [Merlin] but is not a drop-in replacement.
//! It supports multi-round protocols and domain separation, and
//! addresses of Merlin's core design limitations:
//! - Support for arbitrary hash function, including algebraic hashes.
//! To build a secure Fiat-Shamir transform, a permutation function is required.
//! You can choose from SHA3, Poseidon, Anemoi, instantiated over
//! $\mathbb{F}_{2^8}$ or any large-characteristic field $\mathbb{F}_p$.
//! - Retro-compatibility with Sha2 and MD hashes.
//! We have a legacy interface for Sha2 and Blake2 that can be easily extended to Merkle-Damgard hashes
//! and, more in general, any hash function that satisfies the [`digest::Digest`] trait.
//! - Provides an API for preprocessing.
//! In recursive SNARKs, minimizing the number of invocations of the permutation
//! while maintaining security is crucial. We offer tools for preprocessing the Transcript (i.e., the state of the Fiat-Shamir transform) to achieve this goal.
//!
//! - Secure randomness generation for the prover.
//! We provide a secure source of randomness for the prover that is bound to the protocol transcript, and seeded by the oeprating system.
//!
//! # Protocol Composition
//!
//! Protocols can be composed in a secure manner at compile time by combining the IO Patterns of each protocol.
//! This serves as a security feature, preventing the prover
//! from unexpectedly branching without following a specific set of commands.
//!
//! # Possible extra features
//!
//! - byte-oriented squeeze interface such that:
//!    `squeeze(1); squeeze(1)` is the same to `squeeze(2)` in Fiat-Shamir?
//!
//! [SAFE]: https://eprint.iacr.org/2023/522
//! [Merlin]: https://github.com/dalek-cryptography/merlin
//! [`digest::Digest`]: https://docs.rs/digest/latest/digest/trait.Digest.html

#[cfg(target_endian = "big")]
compile_error!(
    r#"
This crate doesn't support big-endian targets.
"#
);

/// Extensions for arkworks types.
#[cfg(feature = "arkworks")]
pub mod arkworks_plugins;

/// Support for legacy hash functions (SHA2).
pub mod legacy;

/// Error types.
mod errors;
/// SHA3 sponge function.
pub mod keccak;

/// Prover's internal state.
mod arthur;
/// Basic units over which a sponge operates.
mod lane;
/// Verifier transcript.
mod merlin;
/// SAFE API for sponge functions.
mod safe;
/// Support for sponge functions.
mod sponge;

pub use arthur::{Transcript, TranscriptBuilder};
pub use errors::InvalidTag;
pub use merlin::Merlin;
pub use safe::{Duplexer, IOPattern, Safe};

// Traits that could be exposed externally in the future
// for constructing custom sponges, for now only visible internally.
pub(crate) use lane::Lane;
pub(crate) use sponge::DuplexSponge;

pub type DefaultRng = rand::rngs::OsRng;
pub type DefaultHash = keccak::Keccak;
pub type DefaultTranscript = Transcript<DefaultHash>;
