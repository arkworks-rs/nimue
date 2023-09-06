/// SHA3 sponge function.
pub mod keccak;
/// Support for legacy hash functions (SHA2).
pub mod legacy;
pub mod sponge;

pub use keccak::Keccak;
use zeroize::Zeroize;

/// Basic units over which a sponge operates.
pub trait Unit: Clone + Default + Sized + Zeroize {}

/// A DuplexHash is an abstract interface for absorbing and squeezing data.
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

impl Unit for u8 {}

//     /// Return the number of random bytes that can be extracted from a random lane.
//     ///
//     /// If `L` is randomly distributed, how many bytes can be extracted from it?
//     fn extractable_bytelen() -> usize;

//     /// Return the number of bytes needed to express a lane.
//     fn compressed_size() -> usize;

//     /// Assuming `a` is randomly distributed in `L`, write
//     /// `a` with random bytes.
//     /// This function assumes that `src` contains enough bytes to fill `dst`.
//     fn to_random_bytes(src: &[Self], dst: &mut [u8]);
