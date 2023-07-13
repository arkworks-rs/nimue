use zeroize::Zeroize;
use serde::{Serialize, Deserialize};

/// A Lane is the basic unit a sponge function works on.
/// We need only two things from a lane: the ability to convert it to bytes and back.
pub trait Lane: Clone + Default + Serialize + for<'a> Deserialize<'a> + Sized + Zeroize {
    /// Return the number of random bytes that can be extracted from a random lane.
    ///
    /// If `L` is randomly distributed, how many bytes can be extracted from it?
    fn extractable_bytelen() -> usize;

    /// Return the number of bytes needed to express a lane.
    fn compressed_size() -> usize;

    /// Assuming `a` is randomly distributed in `L`, write
    /// `a` with random bytes.
    /// This function assumes that `src` contains enough bytes to fill `dst`.
    fn to_random_bytes(src: &[Self], dst: &mut [u8]);

    fn from_bytes(src: &[u8]) -> Vec<Self>;
}

impl Lane for u8 {
    fn extractable_bytelen() -> usize {
        1
    }

    fn compressed_size() -> usize {
        1
    }

    fn to_random_bytes(src: &[Self], dst: &mut [u8]) {
        dst.copy_from_slice(&src[..dst.len()])
    }

    fn from_bytes(src: &[u8]) -> Vec<Self> {
        src.to_vec()
    }
}
