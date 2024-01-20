/// The [`nimue`] package has two types of errors:
/// [`IOPatternError`], which is the error exposed in the low-level interface for bytes and native elements,
/// which arises whenever the IO Pattern specified and the IO pattern exectuted mismatch.
/// [`ProofError`], which is the error exposed to high-level interfaces dealing with structured types and
/// for end-user applications.
/// Three types of errors can happen when dealing with [`ProofError`]:
///
/// - Serialization/Deseralization errors ([`ProofError::SerializationError`]):
///   This includes all potential problems when extracting a particular type from sequences of bytes.
///
/// - Invalid Proof format ([`ProofError::InvalidIO`]):
///   At a higher level, a proof object have to respect the same length and the same types as the protocol description.
///   This error is a wrapper under the [`IOPatternError`] and provides convenient dereference/conversion implementations for
///   moving from/to an [`IOPatternError`].
///
/// - Invalid Proof:
///   An error to signal that the verification equation has failed. Destined for end users.
///
/// A [`core::Result::Result`] wrapper called [`ProofResult`] (having error fixed to [`ProofError`]) is also provided.
use std::{borrow::Borrow, error::Error, fmt::Display};

/// Signals an invalid IO pattern.
///
/// This error indicates a wrong IO Pattern declared
/// upon instantiation of the SAFE sponge.
#[derive(Debug, Clone)]
pub struct IOPatternError(String);


/// An error happened when creating or verifying a proof.
#[derive(Debug, Clone)]
pub enum ProofError {
    /// Signals the verification equation has failed.
    InvalidProof,
    /// The IO pattern specified mismatches the IO pattern used during the protocol execution.
    InvalidIO(IOPatternError),
    /// Serialization/Deserialization led to errors.
    SerializationError,
}

/// The result type when trying to prove or verify a proof using Fiat-Shamir.
pub type ProofResult<T> = Result<T, ProofError>;

impl Display for IOPatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializationError => write!(f, "Serialization Error"),
            Self::InvalidIO(e) => e.fmt(f),
            Self::InvalidProof => write!(f, "Invalid proof"),
        }
    }
}

impl Error for IOPatternError {}
impl Error for ProofError {}

impl From<&str> for IOPatternError {
    fn from(s: &str) -> Self {
        s.to_string().into()
    }
}

impl From<String> for IOPatternError {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl<B: Borrow<IOPatternError>> From<B> for ProofError {
    fn from(value: B) -> Self {
        ProofError::InvalidIO(value.borrow().clone())
    }
}
