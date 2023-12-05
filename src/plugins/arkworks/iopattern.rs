use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use core::ops::Deref;

use super::prelude::*;

pub struct ArkFieldIOPattern<F: Field, H = crate::DefaultHash, U = u8>
where
    H: DuplexHash<U>,
    U: Unit,
{
    io: IOPattern<H, U>,
    _base: std::marker::PhantomData<F>,
}

impl<F, H, U> Deref for ArkFieldIOPattern<F, H, U>
where
    H: DuplexHash<U>,
    U: Unit,
    F: Field,
{
    type Target = IOPattern<H, U>;

    fn deref(&self) -> &Self::Target {
        &self.io
    }
}

impl<F, H, U> From<IOPattern<H, U>> for ArkFieldIOPattern<F, H, U>
where
    F: Field,
    H: DuplexHash<U>,
    U: Unit,
{
    fn from(value: IOPattern<H, U>) -> Self {
        Self {
            io: value,
            _base: std::marker::PhantomData::default(),
        }
    }
}

impl<F, H> ArkFieldIOPattern<F, H, u8>
where
    F: PrimeField,
    H: DuplexHash<u8>,
{
    pub fn new(label: &str) -> Self {
        IOPattern::new(label).into()
    }

    pub fn absorb(self, count: usize, label: &str) -> Self {
        self.io.absorb(count, label).into()
    }

    pub fn squeeze(self, count: usize, label: &str) -> Self {
        self.io.squeeze(count, label).into()
    }

    pub fn ratchet(self) -> Self {
        self.io.ratchet().into()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.io.as_bytes()
    }

    pub fn absorb_scalars(self, count: usize, label: &str) -> Self {
        self.absorb(count * F::ZERO.compressed_size(), label)
    }

    pub fn squeeze_scalars(self, count: usize, label: &str) -> Self {
        self.squeeze(count * (F::MODULUS_BIT_SIZE as usize / 8 + 16), label)
    }
}

pub struct ArkGroupIOPattern<G, H = crate::DefaultHash, U = u8>
where
    G: CurveGroup,
    H: DuplexHash<U>,
    U: Unit,
{
    io: ArkFieldIOPattern<G::ScalarField, H, U>,
    _base: std::marker::PhantomData<G>,
}

impl<G, H, U> Deref for ArkGroupIOPattern<G, H, U>
where
    G: CurveGroup,
    H: DuplexHash<U>,
    U: Unit,
{
    type Target = IOPattern<H, U>;

    fn deref(&self) -> &Self::Target {
        &self.io
    }
}

impl<G, H, U> From<IOPattern<H, U>> for ArkGroupIOPattern<G, H, U>
where
    G: CurveGroup,
    H: DuplexHash<U>,
    U: Unit,
{
    fn from(value: IOPattern<H, U>) -> Self {
        Self {
            io: value.into(),
            _base: std::marker::PhantomData::default(),
        }
    }
}

impl<G, H, U> From<ArkFieldIOPattern<G::ScalarField, H, U>> for ArkGroupIOPattern<G, H, U>
where
    G: CurveGroup,
    H: DuplexHash<U>,
    U: Unit,
{
    fn from(value: ArkFieldIOPattern<G::ScalarField, H, U>) -> Self {
        Self {
            io: value,
            _base: std::marker::PhantomData::default(),
        }
    }
}

impl<G, H> ArkGroupIOPattern<G, H, u8>
where
    G: CurveGroup,
    H: DuplexHash<u8>,
{
    pub fn new(label: &str) -> Self {
        IOPattern::new(label).into()
    }

    pub fn absorb(self, count: usize, label: &str) -> Self {
        self.io.absorb(count, label).into()
    }

    pub fn squeeze(self, count: usize, label: &str) -> Self {
        self.io.squeeze(count, label).into()
    }

    pub fn ratchet(self) -> Self {
        self.io.ratchet().into()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.io.as_bytes()
    }

    pub fn absorb_scalars(self, count: usize, label: &str) -> Self {
        self.io.absorb_scalars(count, label).into()
    }

    pub fn squeeze_scalars(self, count: usize, label: &str) -> Self {
        self.io.squeeze_scalars(count, label).into()
    }

    pub fn absorb_points(self, count: usize, label: &str) -> Self {
        self.io
            .absorb(count * G::default().compressed_size(), label)
            .into()
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
        ArkGroupIOPattern::<ark_curve25519::EdwardsProjective>::new("github.com/mmaker/nimue")
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
