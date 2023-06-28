use ark_ec::AffineRepr;
use ark_ff::Field;
use core::borrow::Borrow;

use super::{
    super::{Duplexer, IOPattern, Lane, Merlin, Transcript},
    Absorbable,
};

/// An IOPattern
/// that is aware of the sponge used and understands arkworks types,
/// such as fields and group elements.
pub struct AlgebraicIO<S: Duplexer> {
    _sponge: ::core::marker::PhantomData<S>,
    iop: IOPattern,
}

impl<S: Duplexer, B: Borrow<IOPattern>> From<B> for AlgebraicIO<S> {
    fn from(value: B) -> Self {
        AlgebraicIO {
            _sponge: Default::default(),
            iop: value.borrow().clone(),
        }
    }
}

impl<S> AlgebraicIO<S>
where
    S: Duplexer,
{
    pub fn new(domsep: &str) -> Self {
        Self {
            iop: IOPattern::new(domsep),
            _sponge: Default::default(),
        }
    }

    pub fn absorb<T: Absorbable<S::L>>(self, count: usize) -> Self {
        self.iop.absorb(T::absorb_size() * count).into()
    }

    pub fn absorb_bytes(self, count: usize) -> Self {
        let count = usize::div_ceil(count, S::L::compressed_size());
        self.iop.absorb(count).into()
    }

    pub fn absorb_point<A>(self, count: usize) -> Self
    where
        A: AffineRepr + Absorbable<S::L>,
    {
        self.iop.absorb(A::absorb_size() * count).into()
    }

    pub fn absorb_field<F: Field + Absorbable<S::L>>(self, count: usize) -> Self {
        self.iop.absorb(F::absorb_size() * count).into()
    }

    pub fn process(self) -> Self {
        self.iop.process().into()
    }

    pub fn squeeze_bytes(self, count: usize) -> Self {
        let count = usize::div_ceil(count, S::L::extractable_bytelen());
        self.iop.squeeze(count).into()
    }
}

impl<S: Duplexer> From<AlgebraicIO<S>> for IOPattern {
    fn from(value: AlgebraicIO<S>) -> Self {
        value.iop
    }
}

impl<S: Duplexer> From<AlgebraicIO<S>> for Transcript<S> {
    fn from(value: AlgebraicIO<S>) -> Self {
        IOPattern::from(value).into()
    }
}

impl<S: Duplexer> From<AlgebraicIO<S>> for Merlin<S> {
    fn from(value: AlgebraicIO<S>) -> Self {
        IOPattern::from(value).into()
    }
}
