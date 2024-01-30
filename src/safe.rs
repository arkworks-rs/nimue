use core::fmt;
use core::marker::PhantomData;
use std::collections::vec_deque::VecDeque;

use super::errors::IOPatternError;
use super::hash::Unit;
use super::hash::{DuplexHash, Keccak};
use super::iopattern::{IOPattern, Op};

/// A (slightly modified) SAFE API for sponge functions.
///
/// Operations in the SAFE API provide a secure interface for using sponges.
#[derive(Clone)]
pub struct Safe<H, U = u8>
where
    U: Unit,
    H: DuplexHash<U>,
{
    sponge: H,
    stack: VecDeque<Op>,
    _unit: PhantomData<U>,
}

impl<U: Unit, H: DuplexHash<U>> Safe<H, U> {
    /// Initialise a SAFE sponge,
    /// setting up the state of the sponge function and parsing the tag string.
    pub fn new(io_pattern: &IOPattern<H, U>) -> Self {
        let stack = io_pattern.finalize();
        let tag = Self::generate_tag(io_pattern.as_bytes());
        Self::unchecked_load_with_stack(tag, stack)
    }

    /// Finish the block and compress the state.
    pub fn ratchet(&mut self) -> Result<(), IOPatternError> {
        if self.stack.pop_front().unwrap() != Op::Ratchet {
            Err("Invalid tag".into())
        } else {
            self.sponge.ratchet_unchecked();
            Ok(())
        }
    }

    /// Ratchet and return the sponge state.
    pub fn preprocess(self) -> Result<&'static [U], IOPatternError> {
        unimplemented!()
        // self.ratchet()?;
        // Ok(self.sponge.tag().clone())
    }

    /// Perform secure absorption of the elements in `input`.
    ///
    /// Absorb calls can be batched together, or provided separately for streaming-friendly protocols.
    pub fn absorb(&mut self, input: &[U]) -> Result<(), IOPatternError> {
        match self.stack.pop_front() {
            Some(Op::Absorb(length)) if length >= input.len() => {
                if length > input.len() {
                    self.stack.push_front(Op::Absorb(length - input.len()));
                }
                self.sponge.absorb_unchecked(input);
                Ok(())
            }
            None => {
                self.stack.clear();
                Err(format!(
                    "Invalid tag. Stack empty, got {:?}",
                    Op::Absorb(input.len())
                )
                .into())
            }
            Some(op) => {
                self.stack.clear();
                Err(format!(
                    "Invalid tag. Got {:?}, expected {:?}",
                    Op::Absorb(input.len()),
                    op
                )
                .into())
            }
        }
    }

    /// Perform a secure squeeze operation, filling the output buffer with uniformly random bytes.
    ///
    /// For byte-oriented sponges, this operation is equivalent to the squeeze operation.
    /// However, for algebraic hashes, this operation is non-trivial.
    /// This function provides no guarantee of streaming-friendliness.
    pub fn squeeze(&mut self, output: &mut [U]) -> Result<(), IOPatternError> {
        match self.stack.pop_front() {
            Some(Op::Squeeze(length)) if output.len() <= length => {
                self.sponge.squeeze_unchecked(output);
                if length != output.len() {
                    self.stack.push_front(Op::Squeeze(length - output.len()));
                }
                Ok(())
            }
            None => {
                self.stack.clear();
                Err(format!(
                    "Invalid tag. Stack empty, got {:?}",
                    Op::Squeeze(output.len())
                )
                .into())
            }
            Some(op) => {
                self.stack.clear();
                Err(format!(
                    "Invalid tag. Got {:?}, expected {:?}. The stack remaining is: {:?}",
                    Op::Squeeze(output.len()),
                    op,
                    self.stack
                )
                .into())
            }
        }
    }

    fn generate_tag(iop_bytes: &[u8]) -> [u8; 32] {
        let mut keccak = Keccak::default();
        keccak.absorb_unchecked(iop_bytes);
        let mut tag = [0u8; 32];
        keccak.squeeze_unchecked(&mut tag);
        tag
    }

    fn unchecked_load_with_stack(tag: [u8; 32], stack: VecDeque<Op>) -> Self {
        Self {
            sponge: H::new(tag),
            stack,
            _unit: PhantomData,
        }
    }
}

impl<U: Unit, H: DuplexHash<U>> Drop for Safe<H, U> {
    /// Destroy the sponge state.
    fn drop(&mut self) {
        // it's a bit violent to panic here,
        // because any other issue in the protocol transcript causing `Safe` to get out of scope
        // (like another panic) will pollute the traceback.
        // debug_assert!(self.stack.is_empty());
        if !self.stack.is_empty() {
            log::error!("Unfinished operations:\n {:?}", self.stack)
        }
        // XXX. is the compiler going to optimize this out?
        self.sponge.zeroize();
    }
}

impl<U: Unit, H: DuplexHash<U>> fmt::Debug for Safe<H, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ensure that the state isn't accidentally logged,
        // but provide the remaining IO Pattern for debugging.
        write!(f, "SAFE sponge with IO: {:?}", self.stack)
    }
}

impl<U: Unit, H: DuplexHash<U>, B: core::borrow::Borrow<IOPattern<H, U>>> From<B> for Safe<H, U> {
    fn from(value: B) -> Self {
        Self::new(value.borrow())
    }
}
