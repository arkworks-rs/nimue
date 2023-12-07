/// Hash functions traits and implmentations.

/// SHA3 sponge function.
pub mod keccak;
/// Support for legacy hash functions (SHA2).
pub mod legacy;
/// Sponge functions.
pub mod sponge;

#[cfg(feature="arkworks")]
pub mod anemoi;

pub use keccak::Keccak;

use std::io;

/// Basic units over which a sponge operates.
///
/// We require the units to have a precise size in memory, to be clonable,
/// and that we can zeroize them.
pub trait Unit: Clone + Sized + zeroize::Zeroize {
    /// Write a bunch of units in the wire.
    fn write(bunch: &[Self], w: &mut impl io::Write) -> Result<(), io::Error>;
    /// Read a bunch of units from the wire
    fn read(r: &mut impl io::Read, bunch: &mut [Self]) -> Result<(), io::Error>;
}

/// A DuplexHash is an abstract interface for absorbing and squeezing data.
/// The type parameter `U` represents basic unit that the sponge works with.
///
/// **HAZARD**: Don't implement this trait unless you know what you are doing.
/// Consider using the sponges already provided by this library.
pub trait DuplexHash<U: Unit>: Default + Clone + zeroize::Zeroize {
    /// Initializes a new sponge, setting up the state.
    fn new(tag: [u8; 32]) -> Self;

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
