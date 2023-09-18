use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Fp, FpConfig, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use core::ops::Deref;

use super::prelude::*;

impl<H, G> ArkIOPattern<G, u8> for IOPattern<H, u8>
where
    H: DuplexHash<u8>,
    G: CurveGroup,
    G::ScalarField: PrimeField,
{
    fn absorb_points(self, count: usize, label: &'static str) -> Self {
        self.absorb(count * G::Affine::generator().compressed_size(), label)
    }

    fn absorb_scalars(self, count: usize, label: &'static str) -> Self {
        self.absorb(count * G::ScalarField::zero().compressed_size(), label)
    }

    fn squeeze_scalars(self, count: usize, label: &'static str) -> Self {
        self.squeeze(count * super::f_bytes::<G::ScalarField>(), label)
    }
}

impl<C, const N: usize, H, G> ArkIOPattern<G, Fp<C, N>> for IOPattern<H, G::BaseField>
where
    C: FpConfig<N>,
    H: DuplexHash<Fp<C, N>>,
    G: CurveGroup<BaseField = Fp<C, N>>,
{
    fn absorb_scalars(self, _count: usize, _label: &'static str) -> Self {
        unimplemented!()
    }

    fn absorb_points(self, count: usize, label: &'static str) -> Self {
        self.absorb(count * 2, label)
    }

    fn squeeze_scalars(self, _count: usize, _label: &'static str) -> Self {
        unimplemented!()
    }
}

pub struct AlgebraicIOPattern<G, H = crate::DefaultHash, U = u8>
where
    H: DuplexHash<U>,
    G: CurveGroup,
    U: Unit,
    IOPattern<H, U>: ArkIOPattern<G, U>,
{
    io: IOPattern<H, U>,
    _group: std::marker::PhantomData<G>,
}

impl<G, H, U> AlgebraicIOPattern<G, H, U>
where
    H: DuplexHash<U>,
    G: CurveGroup,
    U: Unit,
    IOPattern<H, U>: ArkIOPattern<G, U>,
{
    pub fn new(domsep: &'static str) -> Self {
        Self {
            io: IOPattern::new(domsep),
            _group: std::marker::PhantomData::default(),
        }
    }

    pub fn ratchet(self) -> Self {
        self.io.ratchet().into()
    }

    pub fn absorb_scalars(self, count: usize, label: &'static str) -> Self {
        self.io.absorb_scalars(count, label).into()
    }

    pub fn absorb_points(self, count: usize, label: &'static str) -> Self {
        self.io.absorb_points(count, label).into()
    }

    pub fn squeeze_scalars(self, count: usize, label: &'static str) -> Self {
        self.io.squeeze_scalars(count, label).into()
    }

    pub fn absorb(self, count: usize, label: &'static str) -> Self {
        self.io.absorb(count, label).into()
    }

    pub fn squeeze(self, count: usize, label: &'static str) -> Self {
        self.io.squeeze(count, label).into()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.io.as_bytes()
    }
}

impl<G, H, U> Deref for AlgebraicIOPattern<G, H, U>
where
    H: DuplexHash<U>,
    G: CurveGroup,
    U: Unit,
    IOPattern<H, U>: ArkIOPattern<G, U>,
{
    type Target = IOPattern<H, U>;

    fn deref(&self) -> &Self::Target {
        &self.io
    }
}

impl<G, H, U> From<IOPattern<H, U>> for AlgebraicIOPattern<G, H, U>
where
    H: DuplexHash<U>,
    G: CurveGroup,
    U: Unit,
    IOPattern<H, U>: ArkIOPattern<G, U>,
{
    fn from(value: IOPattern<H, U>) -> Self {
        Self {
            io: value,
            _group: std::marker::PhantomData::default(),
        }
    }
}

impl<G, H, U> From<AlgebraicIOPattern<G, H, U>> for IOPattern<H, U>
where
    H: DuplexHash<U>,
    G: CurveGroup,
    U: Unit,
    IOPattern<H, U>: ArkIOPattern<G, U>,
{
    fn from(value: AlgebraicIOPattern<G, H, U>) -> Self {
        value.io
    }
}

#[test]
fn test_iopattern() {
    // OPTION 1 (fails)
    // let io_pattern = IOPattern::new("github.com/mmaker/nimue")
    //     .absorb_points(1, "g")
    //     .absorb_points(1, "pk")
    //     .ratchet()
    //     .absorb_points(1, "com")
    //     .squeeze_scalars(1, "chal")
    //     .absorb_scalars(1, "resp");

    // // OPTION 2
    // fn foo<G: ark_ec::CurveGroup, H: DuplexHash<u8>>() -> IOPattern<H, u8>
    // where
    //     IOPattern<H, u8>: ArkIOPattern<G, u8>,
    // {
    //     IOPattern::new("github.com/mmaker/nimue")
    //         .absorb_points(1, "g")
    //         .absorb_points(1, "pk")
    //         .ratchet()
    //         .absorb_points(1, "com")
    //         .squeeze_scalars(1, "chal")
    //         .absorb_scalars(1, "resp")
    // }
    // let io_pattern = foo::<ark_curve25519::EdwardsProjective, crate::DefaultHash>();

    // OPTION 3 (extra type, trait extensions should be on IOPattern or AlgebraicIOPattern?)
    let io_pattern =
        AlgebraicIOPattern::<ark_curve25519::EdwardsProjective>::new("github.com/mmaker/nimue")
            .absorb_points(1, "g")
            .absorb_points(1, "pk")
            .ratchet()
            .absorb_points(1, "com")
            .squeeze_scalars(1, "chal")
            .absorb_scalars(1, "resp");

    assert_eq!(
        io_pattern.as_bytes(),
        b"github.com/mmaker/nimue\0A32g\0A32pk\0R\0A32com\0S47chal\0A32resp"
    )
}
