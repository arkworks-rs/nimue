//!
//! **This crate is work in progress, not suitable for production.**
//!
//! Nimue helps performing Fiat-Shamir on any public-coin protocol.
//! It enables secure provision of randomness for the prover and secure generation
//! of random coins for the verifier.
//! It is inspired by the [SAFE] API, with minor variations.
//!
//!
//! # Overview
//!
//! The library does two things:
//!
//! - Assist in the construction of a protocol transcript for a public-coin zero-knowledge proof ([`Merlin`]),
//! - Assist in the deserialization and verification of a public-coin protocol ([`Arthur`]).
//!
//! The basic idea behind Nimue is that prover and verifier "commit" to the protocol before running the actual protocol.
//! They a string encoding the sequence of messages sent from the prover and the verifier (the [`IOPattern`]), which is used as an  "IV" to initialize the hash function for the Fiat-Shamir heuristic.
//!
//! There are prover just proceeds with concatenation, without ever worrying
//! about encoding length and special flags to embed in the hash function.
//! This allows for
//! better preprocessing,
//! friendliness with algebraic hashes,
//! static composition of protocol (and prevention of composition during the execution of a protocol),
//! easy an easier inspection of the Fiat-Shamir transform.
//!
//! ```
//! use nimue::{IOPattern, DefaultHash};
//!
//! let io = IOPattern::<DefaultHash>::new("👩‍💻🥷🏻👨‍💻 building 🔐🔒🗝️")
//!         // this indicates the prover is sending 10 elements (bytes)
//!         .absorb(10, "first")
//!         // this indicates the verifier is sending 10 elements (bytes)
//!         .squeeze(10, "second");
//! assert_eq!(io.as_bytes(), "👩‍💻🥷🏻👨‍💻 building 🔐🔒🗝️\0A10first\0S10second".as_bytes())
//! ```
//! An [`IOPattern`] is a UTF8-encoded string wrapper. Absorptions are marked by `A` and
//! squeezes by `S`, followed by the respective length
//! (note: length is expressed in terms of [`hash::Unit`], native elements over which the hash function works).
//! A label is added at the end of each absorb/squeeze, to describe the *type* and
//! *the variable* as used in the protocol. Operations are separated by a NULL byte and therefore labels cannot contain
//! NULL bytes themselves, nor they can start with an ASCII digit.
//!
//! # Batteries included
//! The library comes with support for algebraic objects over arkworks and zkcrypto:
//! - with feature flag `--feature=ark`, the module [`plugins::ark`] provides extension traits for arkworks fields and groups;
//! - with feature flag `--feature=group`, the module [`plugins::group`] provides extension traits for zkcrypto's field and group traits.
//! See the [`plugins`] module for more information.
//!
//!
//! # Protocol transcripts
//!
//! Prover and verifier proof transcripts are built respectively with [`Merlin`] and [`Arthur`].
//! Given the IOPattern, it is possible to build a [`Merlin`] instance that can
//! build the protocol transcript, and seed the private randomness for the prover.
//!
//! ```
//! use nimue::*;
//! use rand::Rng;
//!
//! // Create a new protocol that will absorb 1 byte and squeeze 16 bytes.
//! let io = IOPattern::<DefaultHash>::new("example-protocol 🤌").absorb(1, "↪️").squeeze(16, "↩️");
//! let mut merlin = io.to_merlin();
//! // The prover sends the byte 0x42.
//! merlin.add_bytes(&[0x42]).unwrap();
//! // The prover receive a 128-bit challenge.
//! let mut chal = [0u8; 16];
//! merlin.fill_challenge_bytes(&mut chal).unwrap();
//! // The transcript is recording solely the bytes sent by the prover so far.
//! assert_eq!(merlin.transcript(), [0x42]);
//! // Generate some private randomness bound to the protocol transcript.
//! let private = merlin.rng().gen::<[u8; 2]>();
//!
//! assert_eq!(merlin.transcript(), [0x42]);
//! ```
//!
//! (Note: Nimue provides aliases [`DefaultHash`] and [`DefaultRng`] mapping to secure hash functions and random number generators).
//! An [`Merlin`] instance can generate public coins (via a [`Safe`] instance) and private coins.
//! Private coins are generated with a sponge that absorbs whatever the public sponge absorbs, and is seeded by a cryptographic random number generator throughout the protocol by the prover.
//! This way, it is really hard to produce two different challenges for the same prover message.
//!
//! The verifier can use a [`Arthur`] instance to recover the protocol transcript and public coins:
//! ```
//! use nimue::{IOPattern, Arthur};
//! use nimue::hash::Keccak;
//! use nimue::traits::*;
//! use rand::{Rng, rngs::OsRng};
//!
//! let io = IOPattern::<Keccak>::new("example-protocol 🧀").absorb(1, "in 🍽️").squeeze(16, "out 🤮");
//! let transcript = [0x42];
//! let mut arthur = io.to_arthur(&transcript);
//!
//! // Read the first message.
//! let [first_message] = arthur.next_bytes().unwrap();
//! assert_eq!(first_message, 0x42);
//!
//! // Squeeze out randomness.
//! let chal = arthur.challenge_bytes::<16>().expect("Squeezing 128 bits");
//! ```
//!
//! # Acknowledgements
//!
//! This work is heavily inspired from:
//! - Libsignal's [shosha256], by Trevor Perrin. It provides an absorb/squeeze interface over legacy hash functions.
//! - the [SAFE] API, by Dmitry Khovratovich, JP Aumasson, Porçu Quine, Bart Mennink. To my knowledge they are the first to introduce this idea of using an IO Pattern to build a transcript and the SAFE API.
//! - [Arthur], by Henry de Valence. To my knowledge it introduced this idea of a `Transcript` object carrying over the state of the hash function throughout the protocol.
//!
//!
//! [shosha256]: https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/shosha256.rs
//! [SAFE]: https://eprint.iacr.org/2023/522
//! [Arthur]: https://github.com/dalek-cryptography/arthur
//! [`digest::Digest`]: https://docs.rs/digest/latest/digest/trait.Digest.html

#[cfg(target_endian = "big")]
compile_error!(
    r#"
This crate doesn't support big-endian targets.
"#
);

/// Verifier state and transcript deserialization.
mod arthur;
/// Built-in proof results.
mod errors;
/// Hash functions traits and implementations.
pub mod hash;
/// IO Pattern
mod iopattern;
/// Prover's internal state and transcript generation.
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
pub use hash::{legacy::DigestBridge, DuplexHash, Unit};
pub use iopattern::IOPattern;
pub use merlin::Merlin;
pub use safe::Safe;
pub use traits::*;

/// Default random number generator used ([`rand::rngs::OsRng`]).
pub type DefaultRng = rand::rngs::OsRng;

/// Default hash function used ([`hash::Keccak`]).
pub type DefaultHash = hash::Keccak;
