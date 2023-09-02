use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use core::borrow::Borrow;

use crate::DefaultHash;

use super::super::{Arthur, Duplexer, IOPattern, Lane, Merlin};
use super::Absorbable;

/// An IOPattern
/// that is aware of the sponge used and understands arkworks types,
/// such as fields and group elements.
pub struct AlgebraicIO<H = DefaultHash>
where H: Duplexer {
    _sponge: ::core::marker::PhantomData<H>,
    iop: IOPattern,
}

impl<H: Duplexer, B: Borrow<IOPattern>> From<B> for AlgebraicIO<H> {
    fn from(value: B) -> Self {
        AlgebraicIO {
            _sponge: Default::default(),
            iop: value.borrow().clone(),
        }
    }
}

impl<H> AlgebraicIO<H>
where
    H: Duplexer,
{
    pub fn new(domsep: &str) -> Self {
        Self {
            iop: IOPattern::new(domsep),
            _sponge: Default::default(),
        }
    }

    pub fn absorb<T: Absorbable<H::L>>(self, count: usize) -> Self {
        self.iop.absorb(T::absorb_size() * count, "nat").into()
    }

    pub fn absorb_bytes(self, count: usize) -> Self {
        let count = crate::div_ceil!(count, H::L::compressed_size());
        self.iop.absorb(count, "").into()
    }

    pub fn absorb_point<G>(self, count: usize) -> Self
    where
        G: CurveGroup + Absorbable<H::L>,
    {
        self.iop.absorb(G::absorb_size() * count, "GG").into()
    }

    pub fn absorb_field<F: Field + Absorbable<H::L>>(self, count: usize) -> Self {
        self.iop.absorb(F::absorb_size() * count, "GG").into()
    }

    pub fn process(self) -> Self {
        self.iop.ratchet().into()
    }

    pub fn squeeze_bytes(self, count: usize) -> Self {
        let count = crate::div_ceil!(count, H::L::extractable_bytelen());
        self.iop.squeeze(count, "").into()
    }

    pub fn squeeze_field<F: PrimeField>(self, count: usize) -> Self {
        // XXX. check if typeof::<F>() == typeof::<S::L>() and if so use native squeeze
        self.squeeze_bytes(super::random_felt_bytelen::<F>() * count)
            .into()
    }
}

impl<H: Duplexer> From<AlgebraicIO<H>> for IOPattern {
    fn from(value: AlgebraicIO<H>) -> Self {
        value.iop
    }
}

impl<H: Duplexer> From<AlgebraicIO<H>> for Arthur<H> {
    fn from(value: AlgebraicIO<H>) -> Self {
        IOPattern::from(value).into()
    }
}

impl<H: Duplexer> From<AlgebraicIO<H>> for Merlin<H> {
    fn from(value: AlgebraicIO<H>) -> Self {
        IOPattern::from(value).into()
    }
}
