//! Legacy hash functions interface.
//!
//! This code is inspired from libsignal's poksho:
//! <https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/shosha256.rs>.
//! With the variation that here, squeeze satisfies streaming and the implementation is for any Digest.
//!
//! ```text
//! squeeze(1); squeeze(1); squeeze(1) = squeeze(3);
//! ```

use core::mem::size_of;

use digest::{core_api::BlockSizeUser, typenum::Unsigned, Digest, FixedOutputReset, Reset};
use generic_array::GenericArray;
use zeroize::Zeroize;

use super::DuplexHash;

/// A Bridge to our sponge interface for legacy `Digest` implementations.
#[derive(Clone)]
pub struct DigestBridge<D: Digest + Clone + Reset> {
    /// The underlying hasher.
    hasher: D,
    /// Cached digest
    cv: GenericArray<u8, D::OutputSize>,
    /// Current operation, keeping state between absorb and squeeze
    /// across multiple calls when streaming.
    mode: Mode,
    /// Digest bytes left over from a previous squeeze.
    leftovers: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
enum Mode {
    Absorb,
    Ratcheted(usize),
}

impl<D: BlockSizeUser + Digest + Clone + Reset> DigestBridge<D> {
    const BLOCK_SIZE: usize = D::BlockSize::USIZE;
    const DIGEST_SIZE: usize = D::OutputSize::USIZE;

    fn mask_squeeze(i: usize, cv: &[u8]) -> GenericArray<u8, D::BlockSize> {
        assert_eq!(cv.len(), Self::DIGEST_SIZE);

        let squeeze_header_len: usize =
            D::block_size() - <D as Digest>::output_size() - size_of::<usize>();

        let mut mask = GenericArray::default();
        let mutable_mask = mask.as_mut_slice();
        mutable_mask[0] = 0x80;
        mutable_mask[squeeze_header_len..squeeze_header_len + Self::DIGEST_SIZE]
            .copy_from_slice(cv);
        mutable_mask[Self::BLOCK_SIZE - size_of::<usize>()..]
            .copy_from_slice(i.to_le_bytes().as_slice());

        mask
    }

    fn mask_absorb() -> GenericArray<u8, D::BlockSize> {
        GenericArray::default()
    }
}

impl<D: Clone + Digest + Reset> Zeroize for DigestBridge<D> {
    fn zeroize(&mut self) {
        self.cv.zeroize();
        Digest::reset(&mut self.hasher);
    }
}

impl<D: Clone + Digest + Reset> Drop for DigestBridge<D> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<D: BlockSizeUser + Digest + Clone + FixedOutputReset> Default for DigestBridge<D> {
    fn default() -> Self {
        let mut hasher = D::new();
        Digest::update(&mut hasher, &Self::mask_absorb());
        Self {
            hasher,
            cv: GenericArray::default(),
            mode: Mode::Ratcheted(0),
            leftovers: Vec::new(),
        }
    }
}

impl<D: BlockSizeUser + Digest + Clone + FixedOutputReset> DuplexHash for DigestBridge<D> {
    type U = u8;

    fn new(tag: [u8; 32]) -> Self {
        let mut bridge = Self::default();
        Digest::update(&mut bridge.hasher, &tag);
        Digest::update(&mut bridge.hasher, &Self::mask_squeeze(0, &tag));
        bridge
    }

    fn absorb_unchecked(&mut self, input: &[Self::U]) -> &mut Self {
        if let Mode::Ratcheted(count) = self.mode {
            // append to the state the squeeze mask
            // with the length of the data read so far
            // and the current digest
            Digest::update(&mut self.hasher, &Self::mask_squeeze(count, &self.cv));
            // add the absorb mask
            Digest::update(&mut self.hasher, &Self::mask_absorb());
            // set the sponge state in absorb mode
            self.mode = Mode::Absorb;
            self.leftovers.zeroize();
            self.leftovers.clear();
        }
        // add the input to the hasher
        Digest::update(&mut self.hasher, input);
        self
    }

    fn ratchet_unchecked(&mut self) -> &mut Self {
        if self.mode == Mode::Absorb {
            let digest = self.hasher.finalize_reset();
            // remove all data in `leftovers`
            self.leftovers.zeroize();
            self.leftovers.clear();
            self.cv.copy_from_slice(&digest)
        }
        self
    }

    // fn tag(self) -> &'static [u8] {
    //     self.cv.clone().as_ref()
    // }

    fn squeeze_unchecked(&mut self, output: &mut [Self::U]) -> &mut Self {
        // Nothing to squeeze
        if output.is_empty() {
            self
        }
        // If we still have some digest not yet squeezed
        // from previous invocations, write it to the output.
        else if !self.leftovers.is_empty() {
            let len = usize::min(output.len(), self.leftovers.len());
            self.leftovers[..len].copy_from_slice(&output[..len]);
            self.leftovers.drain(..len);
            // go back to the beginning
            self.squeeze_unchecked(&mut output[len..])
        }
        // If absorbing, change mode and set the state properly
        else if let Mode::Absorb = self.mode {
            self.mode = Mode::Ratcheted(0);
            self.cv.copy_from_slice(&self.hasher.finalize_reset());
            // go back to the beginning
            self.squeeze_unchecked(output)
        // Squeeze another digest
        } else if let Mode::Ratcheted(i) = self.mode {
            let chunk_len = usize::min(output.len(), Self::DIGEST_SIZE);
            // self.hasher is a freshly initialized state.
            // Add the squeeze mask, current digest, and index
            Digest::update(&mut self.hasher, &Self::mask_squeeze(i, &self.cv));
            let digest = self.hasher.finalize_reset();
            // Copy the digest into the output, and store the rest for later
            output[..chunk_len].copy_from_slice(&digest[..chunk_len]);
            self.leftovers.extend_from_slice(&output[chunk_len..]);
            // Update the state
            self.mode = Mode::Ratcheted(i + 1);
            self.squeeze_unchecked(&mut output[chunk_len..])
        } else {
            unreachable!()
        }
    }
}
