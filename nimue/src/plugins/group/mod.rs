//! This adds support also for [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) with feature flag `group`.
mod common;
mod iopattern;
mod reader;
mod writer;

super::traits::field_traits!(group::ff::Field);
super::traits::group_traits!(group::Group, Scalar: group::ff::Field);
