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
#[cfg(feature = "ark")]
pub mod ark;

/// (In-progress) [group](https://github.com/zkcrypto/group) bindings.
#[cfg(feature = "group")]
pub mod group;

/// Compute the bits needed in order to obtain a
/// (pseudo-random) uniform distribution in F.
pub(super) const fn bytes_uniform_modp(modulus_bits: u32) -> usize {
    (modulus_bits as usize + 128) / 8
}

pub(super) const fn bytes_modp(modulus_bits: u32) -> usize {
    (modulus_bits as usize + 7) / 8
}

/// Unit-tests for inter-operability among libraries.
#[cfg(all(test, feature = "ark", feature = "group"))]
mod tests;
mod traits;
