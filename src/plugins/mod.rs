//!  Bindings for some popular libearies using zero-knowledge.

/// Extension traits macros, for both arkworks and group.
mod traits;

#[cfg(feature = "ark")]
/// Arkworks's [algebra](https://github.com/arkworks-rs/algebra) bindings.
pub mod ark;

#[cfg(feature = "group")]
/// (In-progress) [group](https://github.com/zkcrypto/group) bindings.
/// This plugin is experimental and has not yet been thoroughly tested.
pub mod group;

#[cfg(feature = "pow")]
/// Experimental PoW support
pub mod proof_of_work;

/// Bits needed in order to obtain a (pseudo-random) uniform distribution in F.
pub(super) const fn bytes_uniform_modp(modulus_bits: u32) -> usize {
    (modulus_bits as usize + 128) / 8
}

/// Bits needed in order to encode an element of F.
pub(super) const fn bytes_modp(modulus_bits: u32) -> usize {
    (modulus_bits as usize + 7) / 8
}

/// Unit-tests for inter-operability among libraries.
#[cfg(all(test, feature = "ark", feature = "group"))]
mod tests;
