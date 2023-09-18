use std::{error::Error, fmt::Display};

/// Signals an invalid IO pattern.
///
/// This error indicates a wrong IO Pattern declared
/// upon instantiation of the SAFE sponge.
#[derive(Debug, Clone)]
pub struct InvalidTag(String);

impl Display for InvalidTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl Error for InvalidTag {}

impl From<&str> for InvalidTag {
    fn from(s: &str) -> Self {
        s.to_string().into()
    }
}

impl From<String> for InvalidTag {
    fn from(s: String) -> Self {
        Self(s)
    }
}
