use crate::{Lane, Merlin};

use super::super::{Duplexer, InvalidTag, Transcript};
use super::Absorbable;
use rand::{CryptoRng, RngCore};

/// A trait that equips a function with a generic method for absorbing types.
pub trait Absorbs<L: Lane> {
    fn append_element<A: Absorbable<L>>(&mut self, e: &A) -> Result<(), InvalidTag>;

    fn append_elements<A: Absorbable<L>>(&mut self, input: &[A]) -> Result<(), InvalidTag> {
        input.iter().map(|e| self.append_element(e)).collect()
    }
}

impl<S, R> Absorbs<S::L> for Transcript<S, R>
where
    S: Duplexer,
    R: RngCore + CryptoRng,
{
    fn append_element<A: Absorbable<S::L>>(&mut self, input: &A) -> Result<(), InvalidTag> {
        let input = Absorbable::<S::L>::to_absorbable(input);
        self.merlin.append(&input).map(|_| ())
    }
}

impl<S> Absorbs<S::L> for Merlin<S>
where
    S: Duplexer,
{
    fn append_element<A: Absorbable<S::L>>(&mut self, input: &A) -> Result<(), InvalidTag> {
        let input = Absorbable::<S::L>::to_absorbable(input);
        self.append(&input).map(|_| ())
    }
}
