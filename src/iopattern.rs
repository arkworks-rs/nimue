// XXX. before, absorb and squeeze were accepting arguments of type
// use ::core::num::NonZeroUsize;
// which was a pain to use
// (plain integers don't cast to NonZeroUsize automatically)

use crate::ByteIOPattern;
use std::collections::VecDeque;
use std::marker::PhantomData;

use super::errors::IOPatternError;
use super::hash::{DuplexHash, Unit};

/// This is the separator between operations in the IO Pattern
/// and as such is the only forbidden characted in labels.
const SEP_BYTE: &str = "\0";

/// Sponge operations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Op {
    /// Indicates absorption of `usize` lanes.
    ///
    /// In a tag, absorb is indicated with 'A'.
    Absorb(usize),
    /// Indicates squeezing of `usize` lanes.
    ///
    /// In a tag, squeeze is indicated with 'S'.
    Squeeze(usize),
    /// Indicates a ratchet operation.
    ///
    /// For sponge functions, we this means squeeze sizeof(capacity) lanes
    /// and initialize a new state filling the capacity.
    /// This allows for a more efficient preprocessing, and for removal of
    /// private information stored in the rate.
    Ratchet,
}

impl Op {
    /// Create a new OP from the portion of a tag.
    fn new(id: char, count: Option<usize>) -> Result<Self, IOPatternError> {
        match (id, count) {
            ('A', Some(c)) if c > 0 => Ok(Op::Absorb(c)),
            ('R', None) | ('R', Some(0)) => Ok(Op::Ratchet),
            ('S', Some(c)) if c > 0 => Ok(Op::Squeeze(c)),
            _ => Err("Invalid tag".into()),
        }
    }
}

/// The IO Pattern of an interactive protocol.
///
/// An IO Pattern is a string denoting a
/// sequence of operations to be performed on a [`crate::DuplexHash`].
/// The IO Pattern is prepended by a domain separator, a NULL-terminated string
/// that is used to prevent collisions between different protocols.
/// Each operation (absorb, squeeze, ratchet) is identified by a
/// single character, followed by the number of units (bytes, or field elements)
/// to be absorbed/squeezed, and a NULL-terminated label identifying the element.
/// The whole is separated by a NULL byte.
///
/// For example, the IO Pattern
/// ```text
/// iacr.org\0A32\0S64\0A32\0A32
/// ```
///
/// Denotes a protocol absorbing 32 native elements, squeezing 64 native elements,
/// and finally absorbing 64 native elements.
#[derive(Clone)]
pub struct IOPattern<H, U = u8>
where
    U: Unit,
    H: DuplexHash<U>,
{
    io: String,
    _hash: PhantomData<(H, U)>,
}

impl<H: DuplexHash<U>, U: Unit> IOPattern<H, U> {
    fn from_string(io: String) -> Self {
        Self {
            io,
            _hash: PhantomData,
        }
    }

    /// Create a new IOPattern with the domain separator.
    pub fn new(domsep: &str) -> Self {
        assert!(!domsep.contains(SEP_BYTE));
        Self::from_string(domsep.to_string())
    }

    pub fn absorb(self, count: usize, label: &str) -> Self {
        assert!(count > 0, "Count must be positive");
        assert!(!label.contains(SEP_BYTE));
        assert!(label.is_empty() || label[..1].parse::<u8>().is_err());

        Self::from_string(self.io + SEP_BYTE + &format!("A{}", count) + label)
    }

    pub fn squeeze(self, count: usize, label: &str) -> Self {
        assert!(count > 0, "Count must be positive");
        assert!(!label.contains(SEP_BYTE));
        assert!(label.is_empty() || label[..1].parse::<u8>().is_err());

        Self::from_string(self.io + SEP_BYTE + &format!("S{}", count) + label)
    }

    pub fn ratchet(self) -> Self {
        Self::from_string(self.io + SEP_BYTE + "R")
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.io.as_bytes()
    }

    pub(crate) fn finalize(&self) -> VecDeque<Op> {
        // Guaranteed to succeed as instances are all valid iopatterns
        Self::parse_io(self.io.as_bytes())
            .expect("Internal error. Please submit issue to m@orru.net")
    }

    fn parse_io(io_pattern: &[u8]) -> Result<VecDeque<Op>, IOPatternError> {
        let mut stack = VecDeque::new();

        // skip the domain separator
        for part in io_pattern.split(|&b| b == SEP_BYTE.as_bytes()[0]).skip(1) {
            let next_id = part[0] as char;
            let next_length = part[1..]
                .iter()
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
    ) -> Result<VecDeque<Op>, IOPatternError> {
        if stack.is_empty() {
            Ok(dst)
        } else {
            // guaranteed never to fail, since:
            assert!(!dst.is_empty() && !stack.is_empty());
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

    pub fn to_arthur(&self) -> crate::Arthur<H, U, crate::DefaultRng> {
        crate::Arthur::new(self, crate::DefaultRng::default())
    }

    pub fn to_merlin<'a>(&self, transcript: &'a [u8]) -> crate::Merlin<'a, H, U> {
        crate::Merlin::<H, U>::new(self, transcript)
    }
}

impl<U: Unit, H: DuplexHash<U>> core::fmt::Debug for IOPattern<H, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Ensure that the state isn't accidentally logged
        write!(f, "IOPattern({:?})", self.io)
    }
}

impl<H: DuplexHash> ByteIOPattern for IOPattern<H> {
    #[inline]
    fn add_bytes(self, count: usize, label: &str) -> Self {
        self.absorb(count, label)
    }

    #[inline]
    fn challenge_bytes(self, count: usize, label: &str) -> Self {
        self.squeeze(count, label)
    }
}
