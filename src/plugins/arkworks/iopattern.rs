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

    pub fn add_bytes(self, count: usize, label: &str) -> Self {
        self.io.absorb(count, label).into()
    }

    pub fn challenge_bytes(self, count: usize, label: &str) -> Self {
        self.io.squeeze(count, label).into()
    }

    pub fn ratchet(self) -> Self {
        self.io.ratchet().into()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.io.as_bytes()
    }

    pub fn add_scalars(self, count: usize, label: &str) -> Self {
        self.add_bytes(count * F::ZERO.compressed_size(), label)
    }

    pub fn challenge_scalars(self, count: usize, label: &str) -> Self {
        self.challenge_bytes(count * (F::MODULUS_BIT_SIZE as usize / 8 + 16), label)
    }

    pub fn to_arthur(&self) -> ArkFieldArthur<F, H, u8> {
        ArkFieldArthur::new(self, crate::DefaultRng::default())
    }

    pub fn to_merlin<'a>(&self, transcript: &'a [u8]) -> ArkFieldMerlin<'a, F, H, u8> {
        ArkFieldMerlin::new(&self, transcript)
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

    pub fn add_bytes(self, count: usize, label: &str) -> Self {
        self.io.add_bytes(count, label).into()
    }

    pub fn challenge_bytes(self, count: usize, label: &str) -> Self {
        self.io.challenge_bytes(count, label).into()
    }

    pub fn ratchet(self) -> Self {
        self.io.ratchet().into()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.io.as_bytes()
    }

    pub fn add_scalars(self, count: usize, label: &str) -> Self {
        self.io.add_scalars(count, label).into()
    }

    pub fn challenge_scalars(self, count: usize, label: &str) -> Self {
        self.io.challenge_scalars(count, label).into()
    }

    pub fn add_points(self, count: usize, label: &str) -> Self {
        self.io
            .add_bytes(count * G::default().compressed_size(), label)
            .into()
    }

    pub fn to_arthur(&self) -> ArkGroupArthur<G, H, u8> {
        ArkGroupArthur::new(self, crate::DefaultRng::default())
    }

    pub fn to_merlin<'a>(&self, transcript: &'a [u8]) -> ArkGroupMerlin<'a, G, H, u8> {
        ArkGroupMerlin::new(&self, transcript)
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
            .add_points(1, "g")
            .add_points(1, "pk")
            .ratchet()
            .add_points(1, "com")
            .challenge_scalars(1, "chal")
            .add_scalars(1, "resp");

    assert_eq!(
        io_pattern.as_bytes(),
        b"github.com/mmaker/nimue\0A32g\0A32pk\0R\0A32com\0S47chal\0A32resp"
    )
}
