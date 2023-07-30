use super::{InvalidTag, Lane};
use std::collections::vec_deque::VecDeque;
use zeroize::Zeroize;

// XXX. before, absorb and squeeze were accepting arguments of type
// use ::core::num::NonZeroUsize;
// which was a pain to use
// (plain integers don't cast to NonZeroUsize automatically)

/// Sponge operations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    /// Indicates absorption of `usize` lanes.
    ///
    /// In a tag, absorption is indicated with an alphabetic string,
    /// most commonly 'A'.
    Absorb(usize),
    /// Indicates squeezing of `usize` lanes.
    ///
    /// In a tag, squeeze is indicated with 'S'.
    Squeeze(usize),
    /// Indicates a divide operation.
    /// Dividing here means finishing the block and absorbing new elements from here.
    /// For sponge functions, we squeeze sizeof(capacity) lanes
    /// and initialize a new state filling the capacity.
    /// This allows for a more efficient preprocessing, and for removal of the secrets.
    ///
    /// In a tag, dividing is indicated with ','
    Divide,
}

impl Op {
    /// Create a new OP from the portion of a tag.
    fn new(id: char, count: Option<usize>) -> Result<Self, InvalidTag> {
        match (id, count) {
            ('S', Some(c)) if c > 0 => Ok(Op::Squeeze(c)),
            (x, Some(c)) if x.is_alphabetic() && c > 0 => Ok(Op::Absorb(c)),
            (',', None) | (',', Some(0)) => Ok(Op::Divide),
            _ => Err("Invalid tag".into()),
        }
    }
}

/// A builder for tag strings to be used within the SAFE API,
/// to construct the verifier transcript.
#[derive(Clone)]
pub struct IOPattern(String);

const SEP_BYTE: u8 = b'\x00';

impl IOPattern {
    pub fn new(domsep: &str) -> Self {
        let mut tag_base = domsep.to_string();
        tag_base.push(SEP_BYTE as char);
        Self(tag_base)
    }

    pub fn absorb(self, count: usize) -> Self {
        assert!(count > 0, "Count must be positive");

        Self(self.0 + &format!("A{}", count))
    }

    pub fn squeeze(self, count: usize) -> Self {
        assert!(count > 0, "Count must be positive");

        Self(self.0 + &format!("S{}", count))
    }

    pub fn process(self) -> Self {
        Self(self.0 + &",")
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn finalize(&self) -> VecDeque<Op> {
        // Guaranteed to succeed as instances are all valid iopatterns
        Self::parse_io(self.0.as_bytes())
            .expect("Internal error. Please submit issue to m@orru.net")
    }

    fn parse_io(io_pattern: &[u8]) -> Result<VecDeque<Op>, InvalidTag> {
        let mut stack = VecDeque::new();

        // skip the domain separator.
        let mut index = 0;
        for (i, &b) in io_pattern.iter().enumerate() {
            if b == SEP_BYTE {
                index = i;
            }
        }
        let io_pattern = &io_pattern[index + 1..];

        let mut i: usize = 0;
        while i != io_pattern.len() {
            let next_id = io_pattern[i] as char;
            let mut j = i + 1;
            let mut next_length = 0;
            while j != io_pattern.len() && io_pattern[j].is_ascii_digit() {
                next_length = next_length * 10 + (io_pattern[j] - b'0') as usize;
                j += 1;
            }
            i = j;

            // check that next_length != 0 is performed internally on Op::new
            let next_op = Op::new(next_id, Some(next_length))?;
            stack.push_back(next_op);
        }

        // consecutive calls are merged into one
        match stack.pop_front() {
            None => Ok(stack),
            Some(x) => Self::simplify_stack(VecDeque::from([x]), stack),
        }
    }

    fn simplify_stack(
        mut dst: VecDeque<Op>,
        mut stack: VecDeque<Op>,
    ) -> Result<VecDeque<Op>, InvalidTag> {
        if stack.is_empty() {
            Ok(dst)
        } else {
            // guaranteed never to fail, since:
            assert!(dst.len() > 0 && !stack.is_empty());

            let previous = dst.pop_back().unwrap();
            let next = stack.pop_front().unwrap();

            match (previous, next) {
                (Op::Squeeze(a), Op::Squeeze(b)) => {
                    dst.push_back(Op::Squeeze(a + b));
                    Self::simplify_stack(dst, stack)
                }
                (Op::Absorb(a), Op::Absorb(b)) => {
                    dst.push_back(Op::Absorb(a + b));
                    Self::simplify_stack(dst, stack)
                }
                // (Op::Divide, Op::Divide)
                // is useless but unharmful
                (a, b) => {
                    dst.push_back(a);
                    dst.push_back(b);
                    Self::simplify_stack(dst, stack)
                }
            }
        }
    }
}

impl ::core::fmt::Debug for IOPattern {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        // Ensure that the state isn't accidentally logged
        write!(f, "IOPattern({:?})", self.0)
    }
}

/// A Duplexer is an abstract interface for absorbing and squeezing data.
///
/// **HAZARD**: Don't implement this trait unless you know what you are doing.
/// Consider using the sponges already provided by this library.
pub trait Duplexer: Clone + Zeroize {
    /// The basic unit that the sponge works with.
    /// Must support packing and unpacking to bytes.
    type L: Lane;

    /// Initializes a new sponge, setting up the state.
    fn new() -> Self;

    /// Absorbs new elements in the sponge.
    fn absorb_unchecked(&mut self, input: &[Self::L]) -> &mut Self;

    /// Squeezes out new elements.
    fn squeeze_unchecked(&mut self, output: &mut [Self::L]) -> &mut Self;

    /// Diving.
    ///
    /// This operations makes sure that different elements are processed in different blocks.
    /// Right now, this is done by:
    /// - permuting the state.
    /// - zero rate elements.
    /// This has the effect that state holds no information about the elements absorbed so far.
    /// The resulting state is compressed.
    fn divide_unchecked(&mut self) -> &mut Self {
        self.ratchet_unchecked()
    }

    fn ratchet_unchecked(&mut self) -> &mut Self;

    /// Exports the hash state, allowing for preprocessing.
    ///
    /// This function can be used for duplicating the state of the sponge,
    /// but is limited to exporting the state in a way that is compatible
    /// with the `load` function.
    fn store_unchecked(&self) -> &[Self::L];

    /// Loads the hash state, allowing for preprocessing.
    fn load_unchecked(input: &[Self::L]) -> Self;
}

/// A (slightly modified) SAFE API for sponge functions.
///
/// Operations in the SAFE API provide a secure interface for using sponges.
#[derive(Clone)]
pub struct Safe<D: Duplexer> {
    sponge: D,
    stack: VecDeque<Op>,
}

impl<D: Duplexer> Safe<D> {
    /// Initialise a SAFE sponge,
    /// setting up the state of the sponge function and parsing the tag string.
    pub fn new(io_pattern: &IOPattern) -> Self {
        let stack = io_pattern.finalize();
        let tag = Self::generate_tag(io_pattern.as_bytes());
        Self::unchecked_load_with_stack(&tag, &stack)
    }

    /// Finish the block and compress the state.
    ///
    /// Dividing allows for a more efficient preprocessing.
    pub fn divide(&mut self) -> Result<&mut Self, InvalidTag> {
        if self.stack.pop_front().unwrap() != Op::Divide {
            Err("Invalid tag".into())
        } else {
            self.sponge.divide_unchecked();
            Ok(self)
        }
    }

    /// Divide and return the sponge state.
    pub fn divide_and_store(mut self) -> Result<Vec<<D as Duplexer>::L>, InvalidTag> {
        self.divide()?;
        Ok(self.sponge.store_unchecked().to_vec())
    }

    /// Perform secure absorption of the elements in `input`.
    /// Absorb calls can be batched together, or provided separately for streaming-friendly protocols.
    pub fn absorb(&mut self, input: &[D::L]) -> Result<&mut Self, InvalidTag> {
        match self.stack.pop_front() {
            Some(Op::Absorb(length)) if length >= input.len() => {
                if length > input.len() {
                    self.stack.push_front(Op::Absorb(length - input.len()));
                }
                self.sponge.absorb_unchecked(input);
                Ok(self)
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
                    "Invalid tag. Expected {:?}, got {:?}",
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
    pub fn squeeze_bytes(&mut self, output: &mut [u8]) -> Result<(), InvalidTag> {
        match self.stack.pop_front() {
            Some(Op::Squeeze(length)) if output.len() <= length => {
                let squeeze_len = super::div_ceil!(length, D::L::extractable_bytelen());
                let mut squeeze_lane = vec![D::L::default(); squeeze_len];
                self.sponge.squeeze_unchecked(&mut squeeze_lane);
                let mut squeeze_bytes = vec![0u8; D::L::extractable_bytelen() * squeeze_len];
                D::L::to_random_bytes(&squeeze_lane, squeeze_bytes.as_mut_slice());
                output.copy_from_slice(&squeeze_bytes[..output.len()]);
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
                    "Invalid tag. Expected {:?}, got {:?}",
                    Op::Squeeze(output.len()),
                    op
                )
                .into())
            }
        }
    }

    fn generate_tag(iop_bytes: &[u8]) -> [u8; 32] {
        let mut keccak = crate::keccak::Keccak::new();
        keccak.absorb_unchecked(iop_bytes);
        let mut tag = [0u8; 32];
        keccak.squeeze_unchecked(&mut tag);
        tag
    }

    fn unchecked_load_with_stack(tag: &[u8], stack: &VecDeque<Op>) -> Self {
        let sponge = D::load_unchecked(&D::L::from_bytes(tag));
        Self {
            sponge,
            stack: stack.clone(),
        }
    }
}

impl<S: Duplexer> Drop for Safe<S> {
    /// Destroy the sponge state.
    fn drop(&mut self) {
        assert!(self.stack.is_empty());
        self.sponge.zeroize();
    }
}

impl<S: Duplexer> ::core::fmt::Debug for Safe<S> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        // Ensure that the state isn't accidentally logged,
        // but provide the remaining IO Pattern for debugging.
        write!(f, "SAFE sponge with IO: {:?}", self.stack)
    }
}
