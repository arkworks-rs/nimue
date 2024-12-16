//! This module defines
//! [`DuplexHash`], the basic interface for hash function that can absorb and squeeze data.
//! Hashes in nume operate over some native elements satisfying the trait [`Unit`] which, roughly speaking, requires
//! the basic type to support cloning, size, read/write procedures, and secure deletion.
//!
//! Additionally, the module exports some utilities:
//! - [`hash::sponge::DuplexSponge`] allows to implement a [`crate::DuplexHash`] using a secure permutation function, specifying the rate `R` and the width `N`.
//! This is done using the standard duplex sponge construction in overwrite mode (cf. [Wikipedia](https://en.wikipedia.org/wiki/Sponge_function#Duplex_construction)).
//! - [`hash::legacy::DigestBridge`] takes as input any hash function implementing the NIST API via the standard [`digest::Digest`] trait and makes it suitable for usage in duplex mode for continuous absorb/squeeze.

/// A wrapper around the Keccak-f\[1600\] permutation.
pub mod keccak;
/// Legacy hash functions support (e.g. [`sha2`](https://crates.io/crates/sha2), [`blake2`](https://crates.io/crates/blake2)).
pub mod legacy;
/// Sponge functions.
pub mod sponge;

// Re-export the supported hash functions.
pub use keccak::Keccak;

/// Basic units over which a sponge operates.
///
/// We require the units to have a precise size in memory, to be cloneable,
/// and that we can zeroize them.
pub trait Unit: Clone + Sized + zeroize::Zeroize {
    /// Write a bunch of units in the wire.
    fn write(bunch: &[Self], w: &mut impl std::io::Write) -> Result<(), std::io::Error>;
    /// Read a bunch of units from the wire
    fn read(r: &mut impl std::io::Read, bunch: &mut [Self]) -> Result<(), std::io::Error>;
}

/// A [`DuplexHash`] is an abstract interface for absorbing and squeezing data.
/// The type parameter `U` represents basic unit that the sponge works with.
///
/// We require [`DuplexHash`] implementations to have a [`std::default::Default`] implementation, that initializes
/// to zero the hash function state, and a [`zeroize::Zeroize`] implementation for secure deletion.
///
/// **HAZARD**: Don't implement this trait unless you know what you are doing.
/// Consider using the sponges already provided by this library.
pub trait DuplexHash<U = u8>: Default + Clone + zeroize::Zeroize
where
    U: Unit,
{
    /// Initializes a new sponge, setting up the state.
    fn new(iv: [u8; 32]) -> Self;

    /// Absorbs new elements in the sponge.
    fn absorb_unchecked(&mut self, input: &[U]) -> &mut Self;

    /// Squeezes out new elements.
    fn squeeze_unchecked(&mut self, output: &mut [U]) -> &mut Self;

    /// Ratcheting.
    ///
    /// This operations makes sure that different elements are processed in different blocks.
    /// Right now, this is done by:
    /// - permuting the state.
    /// - zero rate elements.
    /// This has the effect that state holds no information about the elements absorbed so far.
    /// The resulting state is compressed.
    fn ratchet_unchecked(&mut self) -> &mut Self;

    // /// Exports the hash state, allowing for preprocessing.
    // ///
    // /// This function can be used for duplicating the state of the sponge,
    // /// but is limited to exporting the state in a way that is compatible
    // /// with the `load` function.
    // fn tag(self) -> &'static [Self::U];
}

impl Unit for u8 {
    fn write(bunch: &[Self], w: &mut impl std::io::Write) -> Result<(), std::io::Error> {
        w.write_all(bunch)
    }

    fn read(r: &mut impl std::io::Read, bunch: &mut [Self]) -> Result<(), std::io::Error> {
        r.read_exact(bunch)
    }
}
