mod common;
mod reader;

super::traits::field_traits!(group::ff::Field);
super::traits::group_traits!(group::Curve, G::Scalar : group::ff::Field);
