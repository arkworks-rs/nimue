//!  Bindings for some popular libearies using zero-knowledge.
//!
//! Nimue can be enriched with the following features:
//!
//! - `arkwors` enables the module [`plugins::arkworks`] providing bindings for the
//! arkworks algebra crates.
//! - `dalek` enables the module [`plugins::dalek`] provides bindings for `curve25519_dalek`.
//!
//! A work-in-progress implementation for `group` is in the making (cf. [issue#3])
//!
//! [issue#3]: https://github.com/arkworks-rs/nimue/issues/3

/// Arkworks's [algebra](https://github.com/arkworks-rs/algebra) bindings.
#[cfg(feature = "arkworks")]
pub mod arkworks;

/// [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) bindings.
#[cfg(feature = "dalek")]
pub mod dalek;

/// (In-progress) [group](https://github.com/zkcrypto/group) bindings.
#[cfg(feature = "zkcrypto")]
pub mod zkcrypto;

/// Compute the bits needed in order to obtain a
/// (pseudo-random) uniform distribution in F.
pub(super) const fn bytes_uniform_modp(modulus_bits: usize) -> usize {
    (modulus_bits as usize + 128) / 8
}

/// Unit-tests for inter-operability among libraries.
#[cfg(all(test, feature = "arkworks", feature = "dalek", feature = "zkcrypto"))]
mod tests;
mod traits;
