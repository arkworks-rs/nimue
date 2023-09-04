/// SHA3 sponge function.
pub mod keccak;
/// Basic units over which a sponge operates.
pub mod unit;
/// Support for legacy hash functions (SHA2).
pub mod legacy;
pub mod sponge;

pub use keccak::Keccak;
pub use unit::Unit;

use zeroize::Zeroize;

/// A Duplexer is an abstract interface for absorbing and squeezing data.
///
/// **HAZARD**: Don't implement this trait unless you know what you are doing.
/// Consider using the sponges already provided by this library.
pub trait DuplexHash: Default + Clone + Zeroize {
    /// The basic unit that the sponge works with.
    /// Must support packing and unpacking to bytes.
    type U: Unit;

    /// Initializes a new sponge, setting up the state.
    fn new(tag: [u8; 32]) -> Self;

    /// Absorbs new elements in the sponge.
    fn absorb_unchecked(&mut self, input: &[Self::U]) -> &mut Self;

    /// Squeezes out new elements.
    fn squeeze_unchecked(&mut self, output: &mut [Self::U]) -> &mut Self;

    /// Ratcheting.
    ///
    /// This operations makes sure that different elements are processed in different blocks.
    /// Right now, this is done by:
    /// - permuting the state.
    /// - zero rate elements.
    /// This has the effect that state holds no information about the elements absorbed so far.
    /// The resulting state is compressed.
    fn ratchet_unchecked(&mut self) -> &mut Self;

    /// Exports the hash state, allowing for preprocessing.
    ///
    /// This function can be used for duplicating the state of the sponge,
    /// but is limited to exporting the state in a way that is compatible
    /// with the `load` function.
    fn tag(&self) -> &[Self::U];

}
