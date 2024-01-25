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
//! # Features
//!
//! Nimue supports multi-round protocols, domain separation, and protocol composition.
//! Inspired from [Merlin], it tries to address some of its core design limitations:
//! - **Support custom hash function**, including algebraic hashes.
//! To build a secure Fiat-Shamir transform, the minimal requirement is a permutation function over some field,
//! be it $\mathbb{F}_{2^8}$ or any large-characteristic prime field $\mathbb{F}_p$.
//! - **Retro-compatibility** with MD hashes.
//! We have a legacy interface for Sha2, Blake2, and any hash function that satisfies the [`digest::Digest`] trait.
//! - **Preprocessing**.
//! In recursive SNARKs, minimizing the number of hash invocations
//! while maintaining security is crucial. We offer tools for preprocessing the Transcript (i.e., the state of the Fiat-Shamir transform) to achieve this goal.
//! - **Private randomness generation**.
//! It is vital to avoid providing two different challenges for the same prover message. We do our best to avoid it by tying down the prover randomness to the protocol transcript, without making the proof deterministic.
//! # IO Patterns
//!
//! The basic idea behind Nimue is that prover and verifier both commit to the entire sequence of absorb
//! and squeeze done throughout the protocol.
//! Once the IO Pattern is fixed, the rest of the protocol can just proceed with concatenation, without ever worrying
//! about encoding length and special flags in a protocol transcript.
//! This allows for
//! better preprocessing,
//! friendliness with algebraic hashes,
//! static composition of protocol (and prevention of composition during the execution of a protocol),
//! easy inspection of the Fiat-Shamir transform.
//!
//! ```
//! use nimue::IOPattern;
//! use nimue::hash::Keccak;
//!
//! let io = IOPattern::<Keccak>::new("a domain separator")
//!         // this indicates the prover is sending 10 elements (bytes)
//!         .absorb(10, "first")
//!         // this indicates the verifier is sending 10 elements (bytes)
//!         .squeeze(10, "second");
//! assert_eq!(io.as_bytes(), b"a domain separator\0A10first\0S10second")
//! ```
//! An [`IOPattern`] is a UTF8-encoded string wrapper. Absorptions are denoted as `format!(A{}, length)` and
//! squeezes as `format!(S{}, length)`. A label is added at the end of the string, meant to describe the *type* and
//! *the variable* as used in the protocol. Operations are separated by a NULL byte and therefore labels cannot contain
//! NULL bytes themselves, nor start with an ASCII digit.
//! Additional type shortcuts can be found in the [`plugins`] module as extension traits.
//!
//!
//! # Protocol transcripts
//!
//! Prover and verifier proof transcripts are built respectively with [`Arthur`] and [`Merlin`].
//! Given the IOPattern, it is possible to build a [`Arthur`] instance that can
//! build the protocol transcript, and seed the private randomness for the prover.
//!
//! ```
//! use nimue::{IOPattern, Arthur};
//! use nimue::hash::Keccak;
//! use nimue::traits::*;
//! use rand::Rng;
//!
//! // create a new protocol that will absorb 1 byte and squeeze 16 bytes.
//! // by default we use keccak, but things like `DigestBridge<sha2::Sha256>` will work too.
//! let io = IOPattern::<Keccak>::new("example-protocol").absorb(1, "send").squeeze(16, "receive");
//! let mut arthur = io.to_arthur();
//! // the prover sends the byte 0x42.
//! arthur.add(&[0x42]).expect("Absorbing one byte");
//! // the prover receive a 128-bit challenge.
//! let mut chal = [0u8; 16];
//! arthur.fill_challenge_bytes(&mut chal).expect("Squeezing 128 bits");
//! assert_eq!(arthur.transcript(), [0x42]);
//! // generate some private randomness bound to the protocol transcript.
//! let private = arthur.rng().gen::<[u8; 2]>();
//!
//! assert_eq!(arthur.transcript(), [0x42]);
//! ```
//!
//! (Note: Nimue provides aliases [`DefaultHash`] and [`DefaultRng`] mapping to secure hash functions and random number generators).
//! An [`Arthur`] instance can generate public coin (via a [`Safe`] instance) and private coins.
//! Private coins are generated with a sponge that absorbs whatever the public sponge absorbs, and is seeded by a cryptographic random number generator throughout the protocol by the prover.
//! This way, it is really hard to produce two different challenges for the same prover message.
//!
//! The verifier can use a [`Merlin`] instance to recover the protocol transcript and public coins:
//! ```
//! use nimue::{IOPattern, Merlin};
//! use nimue::hash::Keccak;
//! use nimue::traits::*;
//! use rand::{Rng, rngs::OsRng};
//!
//! let io = IOPattern::<Keccak>::new("example-protocol").absorb(1, "inhale").squeeze(16, "exhale");
//! let transcript = [0x42];
//! let mut merlin = io.to_merlin(&transcript);
//!
//! // Read the first message.
//! let [first_message] = merlin.next_bytes().unwrap();
//! assert_eq!(first_message, 0x42);
//!
//! // Squeeze out randomness.
//! let chal = merlin.challenge_bytes::<16>().expect("Squeezing 128 bits");
//! ```
//!
//! # Contributing
//!
//! This work is still in early development!
//! If you would like to contribute, adopt it in your project, or simply tell us about your use-case,
//! reach out to us!
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

/// Prover's internal state and transcript generation.
mod arthur;
/// Built-in proof results.
mod errors;
/// Hash functions traits and implmentations.
pub mod hash;
/// Verifier state and transcript deserialization.
mod merlin;
/// APIs for common zkp libraries.
pub mod plugins;
/// SAFE API.
mod safe;
/// Unit-tests.
#[cfg(test)]
mod tests;
/// Traits for byte support.
pub mod traits;

pub use arthur::Arthur;
pub use errors::{IOPatternError, ProofError, ProofResult};
pub use hash::{DuplexHash, Unit};
pub use merlin::Merlin;
pub use safe::{IOPattern, Safe};
pub use traits::*;

/// Default random number generator used ([`rand::rngs::OsRng`]).
pub type DefaultRng = rand::rngs::OsRng;

/// Default hash function used ([`hash::Keccak`]).
pub type DefaultHash = hash::Keccak;
