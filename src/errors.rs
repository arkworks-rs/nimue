use std::{borrow::Borrow, error::Error, fmt::Display};

/// Signals an invalid IO pattern.
///
/// This error indicates a wrong IO Pattern declared
/// upon instantiation of the SAFE sponge.
#[derive(Debug, Clone)]
pub struct IOPatternError(String);

#[derive(Debug, Clone)]
pub enum ProofError {
    InvalidProof,
    InvalidIO(IOPatternError),
    SerializationError,
}

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
