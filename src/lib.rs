//!
//! **This crate is work in progress, not suitable for production.**
//!
//! Nimue helps performing Fiat-Shamir on any public-coin protocol.
//! It enables secure provision of randomness for the prover and secure generation
//! of random coins for the verifier.
//! It is inspired by the [SAFE] API with minor variations.
//!
//! This allows for the implementation of non-interactive protocols in a readable manner,
//! in a unified framework for sponge functions.
//!
//! # Example
//!
//! ```
//! use nimue::{IOPattern, Merlin};
//!
//! // create a new protocol that will absorb 1 byte and squeeze 1 byte.
//! let io = IOPattern::new("example-protocol").absorb(1, "inhale").squeeze(16, "exhale");
//! // by default we use keccak, but `nimue::legacy::DigestBridge<sha2::Sha256>` works too.
//! let mut merlin = Merlin::<nimue::DefaultHash>::new(&io);
//! merlin.append(&[0x42]).expect("Absorbing one byte");
//! let mut chal = [0u8; 16];
//! merlin.challenge_bytes(&mut chal).expect("Squeezing 128 bits");
//! ```
//!
//! The [`IOPattern`] struct is a builder for the IO Pattern of the protocol.
//! It declares how many **native elements** will be absorbed and how many bytes will be squeezed.
//! Protocols can be composed in a secure manner by concatenating the respective [`IOPattern`]s.
//! [`Merlin`] allows to generate public coin for protocol satisfying the IO Pattern.
//! Compatibility with arkworks types is given by the feature flag `arkworks`.
//!
//! The prover can use a [`Arthur`] to generate both the zk randomness as well as the public coins:
//! ```
//! use nimue::{IOPattern, Arthur};
//! use rand::{Rng, rngs::OsRng};
//!
//! let io = IOPattern::new("example-protocol").absorb(1, "inhale").squeeze(16, "exhale");
//! // by default, arthur is seeded with `rand::rngs::OsRng`.
//! let mut arthur = Arthur::<nimue::DefaultHash>::new(&io, OsRng);
//! arthur.append(&[0x42]).expect("Absorbing one byte");
//!
//! // generate 32 bytes of private randomness.
//! let mut rnd = arthur.rng().gen::<[u8; 32]>();
//! let mut chal = [0u8; 16];
//!
//! // continue with the protocol.
//! arthur.challenge_bytes(&mut chal).expect("Squeezing 128 bits");
//! ```
//!
//!
//! # Features
//!
//! Nimue supports multi-round protocols, domain separation, and protocol composition.
//! Inspired from [Merlin], it tries to address some of its core design limitations:
//! - Support for arbitrary sponge functions, including algebraic hashes.
//! To build a secure Fiat-Shamir transform, the minimal requirement is a permutation function over some field,
//! be it $\mathbb{F}_{2^8}$ or any large-characteristic prime field $\mathbb{F}_p$.
//! - Retro-compatibility with MD hashes.
//! We have a legacy interface for Sha2, Blake2, and any hash function that satisfies the [`digest::Digest`] trait.
//! - API for preprocessing.
//! In recursive SNARKs, minimizing the number of hash invocations
//! while maintaining security is crucial. We offer tools for preprocessing the Transcript (i.e., the state of the Fiat-Shamir transform) to achieve this goal.
//! - Randomness generation for the prover.
//! It is vital to avoid providing two different challenges for the same prover message. We do our best to avoid it by tying down the prover randomness to the protocol transcript, without making the proof deterministic.
//!
//! # Work-in-progress features
//!
//! - squeeze native field elements
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
/// Unit-tests.
#[cfg(test)]
mod tests;

pub use arthur::{Arthur, ArthurBuilder};
pub use errors::InvalidTag;
pub use merlin::Merlin;
pub use safe::{Duplexer, IOPattern, Safe};

// Traits that could be exposed externally in the future
// for constructing custom sponges, for now only visible internally.
pub(crate) use lane::Lane;
pub(crate) use sponge::DuplexSponge;

pub type DefaultRng = rand::rngs::OsRng;
pub type DefaultHash = keccak::Keccak;

/// Perform ceil division.
/// XXX. Remove once feature(int_roundings) is on stable.
macro_rules! div_ceil {
    ($a: expr, $b: expr) => {
        ($a + $b - 1) / $b
    };
}
pub(crate) use div_ceil;
