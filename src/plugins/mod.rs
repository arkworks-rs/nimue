//!  Bindings for some popular libearies using zero-knowledge.
//!
//! Nimue can be enriched with the following features:
//!
//! - `arkwors` enables the module [`crate::plugins::arkworks`] providing bindings for the
//! arkworks algebra crates.
//! - `dalek` enables the module [`crate::plugins::dalek`] provides bindings for [`curve25519_dalek`].
//!
//! A work-in-progress implementation for [`group`] is in the making (cf. [issue#3])
//!
//! [issue#3]: https://github.com/arkworks-rs/nimue/issues/3
#[cfg(feature = "arkworks")]
pub mod arkworks;

#[cfg(feature = "dalek")]
pub mod dalek;

#[cfg(feature = "zkcrypto")]
pub mod zkcrypto;

#[cfg(all(test, feature = "arkworks", feature = "dalek", feature = "zkcrypto"))]
mod tests;
