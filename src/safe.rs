use super::hash::DuplexHash;
use super::InvalidTag;
use std::collections::vec_deque::VecDeque;
use super::hash::Keccak;

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
    /// Indicates a ratchet operation.
    /// Dividing here means finishing the block and absorbing new elements from here.
    /// For sponge functions, we squeeze sizeof(capacity) lanes
    /// and initialize a new state filling the capacity.
    /// This allows for a more efficient preprocessing, and for removal of the secrets.
    Ratchet,
}

impl Op {
    /// Create a new OP from the portion of a tag.
    fn new(id: char, count: Option<usize>) -> Result<Self, InvalidTag> {
        match (id, count) {
            ('S', Some(c)) if c > 0 => Ok(Op::Squeeze(c)),
            ('A', Some(c)) if c > 0 => Ok(Op::Absorb(c)),
            ('R', None) | ('R', Some(0)) => Ok(Op::Ratchet),
            _ => Err("Invalid tag".into()),
        }
    }
}

/// A builder for tag strings to be used within the SAFE API,
/// to construct the verifier transcript.
#[derive(Clone)]
pub struct IOPattern(String);

impl IOPattern {
    pub fn new(domsep: &str) -> Self {
        assert!(!domsep.contains(" "));
        Self(domsep.to_string())
    }

    pub fn absorb(self, count: usize, label: &'static str) -> Self {
        assert!(count > 0, "Count must be positive");
        assert!(!label.contains(' '));

        Self(self.0 + &format!(" A{}{}", count, label))
    }

    pub fn squeeze(self, count: usize, label: &'static str) -> Self {
        assert!(count > 0, "Count must be positive");

        Self(self.0 + &format!(" S{}{}", count, label))
    }

    pub fn ratchet(self) -> Self {
        Self(self.0 + &" R")
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

        // skip the domain separator
        for part in io_pattern.split(|&b| b as char == ' ').into_iter().skip(1) {
            let next_id = part[0] as char;
            let next_length = part[1..]
                .into_iter()
                .take_while(|x| x.is_ascii_digit())
                .fold(0, |acc, x| acc * 10 + (x - b'0') as usize);

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

/// A (slightly modified) SAFE API for sponge functions.
///
/// Operations in the SAFE API provide a secure interface for using sponges.
#[derive(Clone)]
pub struct Safe<H: DuplexHash> {
    sponge: H,
    stack: VecDeque<Op>,
}

impl<H: DuplexHash> Safe<H> {
    /// Initialise a SAFE sponge,
    /// setting up the state of the sponge function and parsing the tag string.
    pub fn new(io_pattern: &IOPattern) -> Self {
        let stack = io_pattern.finalize();
        let tag = Self::generate_tag(io_pattern.as_bytes());
        Self::unchecked_load_with_stack(tag, stack)
    }

    /// Finish the block and compress the state.
    ///
    /// Dividing allows for a more efficient preprocessing.
    pub fn ratchet(&mut self) -> Result<(), InvalidTag> {
        if self.stack.pop_front().unwrap() != Op::Ratchet {
            Err("Invalid tag".into())
        } else {
            self.sponge.ratchet_unchecked();
            Ok(())
        }
    }

    /// Divide and return the sponge state.
    pub fn ratchet_and_store(mut self) -> Result<Vec<H::U>, InvalidTag> {
        self.ratchet()?;
        Ok(self.sponge.tag().to_vec())
    }

    /// Perform secure absorption of the elements in `input`.
    /// Absorb calls can be batched together, or provided separately for streaming-friendly protocols.
    pub fn absorb(&mut self, input: &[H::U]) -> Result<(), InvalidTag> {
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
    pub fn squeeze(&mut self, output: &mut [H::U]) -> Result<(), InvalidTag> {
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
                    "Invalid tag. Expected {:?}, got {:?}",
                    Op::Squeeze(output.len()),
                    op
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
        }
    }
}

impl<H: DuplexHash> Drop for Safe<H> {
    /// Destroy the sponge state.
    fn drop(&mut self) {
        // assert!(self.stack.is_empty());
        if self.stack.is_empty() {
            log::error!("Unfinished operations:\n {:?}", self.stack)
        }
        self.sponge.zeroize();
    }
}



impl<H: DuplexHash> ::core::fmt::Debug for Safe<H> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        // Ensure that the state isn't accidentally logged,
        // but provide the remaining IO Pattern for debugging.
        write!(f, "SAFE sponge with IO: {:?}", self.stack)
    }
}

pub trait ByteCompatible {
    fn absorb_bytes(&mut self, input: &[u8]) -> Result<(), InvalidTag>;
    fn squeeze_bytes(&mut self, output: &mut [u8]) -> Result<(), InvalidTag>;
}

impl<H: DuplexHash<U = u8>> ByteCompatible for Safe<H> {
    fn absorb_bytes(&mut self, input: &[u8]) -> Result<(), InvalidTag> {
        self.absorb(input)
    }

    fn squeeze_bytes(&mut self, output: &mut [u8]) -> Result<(), InvalidTag> {
        self.squeeze(output)
    }
}