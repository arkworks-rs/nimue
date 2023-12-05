use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::ops::Deref;

use crate::hash::Unit;
use crate::{DuplexHash, IOPattern, InvalidTag, Merlin};

pub struct ArkFieldMerlin<'a, F, H = crate::DefaultHash, U = u8>
where
    F: Field,
    H: DuplexHash<U>,
    U: Unit,
{
    merlin: Merlin<'a, H, U>,
    _base: std::marker::PhantomData<F>,
}

impl<'a, F, H, U> Deref for ArkFieldMerlin<'a, F, H, U>
where
    F: Field,
    H: DuplexHash<U>,
    U: Unit,
{
    type Target = Merlin<'a, H, U>;

    fn deref(&self) -> &Self::Target {
        &self.merlin
    }
}

impl<'a, F, H, U> core::ops::DerefMut for ArkFieldMerlin<'a, F, H, U>
where
    F: Field,
    H: DuplexHash<U>,
    U: Unit,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.merlin
    }
}

impl<'a, F, H, U> From<Merlin<'a, H, U>> for ArkFieldMerlin<'a, F, H, U>
where
    F: Field,
    H: DuplexHash<U>,
    U: Unit,
{
    fn from(value: Merlin<'a, H, U>) -> Self {
        Self {
            merlin: value,
            _base: std::marker::PhantomData::default(),
        }
    }
}

impl<'a, F, H> ArkFieldMerlin<'a, F, H, u8>
where
    F: PrimeField,
    H: DuplexHash<u8>,
{
    pub fn new(io: &IOPattern<H>, transcript: &'a [u8]) -> Self {
        Merlin::new(io, transcript).into()
    }

    pub fn next_fill(&mut self, input: &mut [u8]) -> Result<(), InvalidTag> {
        self.merlin.next(input)
    }

    pub fn squeeze_fill(&mut self, input: &mut [u8]) -> Result<(), InvalidTag> {
        self.merlin.squeeze(input)
    }

    pub fn transcript(&self) -> &[u8] {
        &self.merlin.transcript
    }

    pub fn public_input(&mut self, input: &[u8]) -> Result<(), InvalidTag> {
        self.merlin.public_input(input)
    }

    pub fn next_fill_scalars(&mut self, output: &mut [F]) -> Result<(), InvalidTag> {
        let point_size = F::default().compressed_size();
        let mut buf = vec![0u8; point_size];

        for o in output.iter_mut() {
            self.merlin.next(&mut buf)?;
            *o = F::deserialize_compressed(buf.as_slice()).expect("Invalid");
        }
        Ok(())
    }

    pub fn squeeze_scalars_fill(&mut self, output: &mut [F]) -> Result<(), InvalidTag> {
        for o in output.iter_mut() {
            let mut buf = vec![0u8; F::MODULUS_BIT_SIZE as usize / 8 + 16];
            self.merlin.squeeze(&mut buf)?;
            *o = F::from_be_bytes_mod_order(&buf);
        }
        Ok(())
    }

    pub fn next<const N: usize>(&mut self) -> Result<[u8; N], InvalidTag> {
        let mut output = [0u8; N];
        self.next_fill(&mut output).map(|()| output)
    }

    pub fn squeeze<const N: usize>(&mut self) -> Result<[u8; N], InvalidTag> {
        let mut output = [0u8; N];
        self.squeeze_fill(&mut output).map(|()| output)
    }

    pub fn next_scalars<const N: usize>(&mut self) -> Result<[F; N], InvalidTag> {
        let mut output = [F::default(); N];
        self.next_fill_scalars(&mut output).map(|()| output)
    }

    pub fn public_scalars(&mut self, input: &[F]) -> Result<(), InvalidTag> {
        let mut buf = Vec::new();
        for i in input {
            i.serialize_compressed(&mut buf)
                .expect("Serialization failed");
        }
        self.merlin.public_input(&buf)
    }

    pub fn squeeze_scalars<const N: usize>(&mut self) -> Result<[F; N], InvalidTag> {
        let mut output = [F::zero(); N];
        self.squeeze_scalars_fill(&mut output).map(|()| output)
    }
}

pub struct ArkGroupMerlin<'a, G: CurveGroup, H = crate::DefaultHash, U = u8>
where
    H: DuplexHash<U>,
    U: Unit,
{
    merlin: ArkFieldMerlin<'a, G::ScalarField, H, U>,
    _base: std::marker::PhantomData<G>,
}

impl<'a, G, H, U> Deref for ArkGroupMerlin<'a, G, H, U>
where
    G: CurveGroup,
    H: DuplexHash<U>,
    U: Unit,
{
    fn deref(&self) -> &Self::Target {
        &self.merlin
    }

    type Target = ArkFieldMerlin<'a, G::ScalarField, H, U>;
}

impl<'a, G, H, U> core::ops::DerefMut for ArkGroupMerlin<'a, G, H, U>
where
    G: CurveGroup,
    H: DuplexHash<U>,
    U: Unit,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.merlin
    }
}

impl<'a, G, H, U> From<ArkFieldMerlin<'a, G::ScalarField, H, U>> for ArkGroupMerlin<'a, G, H, U>
where
    G: CurveGroup,
    H: DuplexHash<U>,
    U: Unit,
{
    fn from(value: ArkFieldMerlin<'a, G::ScalarField, H, U>) -> Self {
        Self {
            merlin: value,
            _base: std::marker::PhantomData::default(),
        }
    }
}

impl<'a, G, H, U> From<ArkGroupMerlin<'a, G, H, U>> for ArkFieldMerlin<'a, G::ScalarField, H, U>
where
    G: CurveGroup,
    H: DuplexHash<U>,
    U: Unit,
{
    fn from(value: ArkGroupMerlin<'a, G, H, U>) -> Self {
        value.merlin
    }
}

impl<'a, G, H, U> From<Merlin<'a, H, U>> for ArkGroupMerlin<'a, G, H, U>
where
    G: CurveGroup,
    H: DuplexHash<U>,
    U: Unit,
{
    fn from(value: Merlin<'a, H, U>) -> Self {
        Self {
            merlin: value.into(),
            _base: std::marker::PhantomData::default(),
        }
    }
}

impl<'a, G, H> ArkGroupMerlin<'a, G, H, u8>
where
    G: CurveGroup,
    H: DuplexHash<u8>,
{
    pub fn new(io: &IOPattern<H>, transcript: &'a [u8]) -> Self {
        Merlin::new(io, transcript).into()
    }

    pub fn next_fill(&mut self, input: &mut [u8]) -> Result<(), InvalidTag> {
        self.merlin.next_fill(input)
    }

    pub fn squeeze_fill(&mut self, input: &mut [u8]) -> Result<(), InvalidTag> {
        self.merlin.squeeze_fill(input)
    }

    pub fn transcript(&self) -> &[u8] {
        &self.merlin.transcript
    }

    pub fn next_fill_scalars(&mut self, output: &mut [G::ScalarField]) -> Result<(), InvalidTag> {
        self.merlin.next_fill_scalars(output)
    }

    pub fn squeeze_scalars_fill(
        &mut self,
        output: &mut [G::ScalarField],
    ) -> Result<(), InvalidTag> {
        self.merlin.squeeze_scalars_fill(output)
    }

    pub fn next<const N: usize>(&mut self) -> Result<[u8; N], InvalidTag> {
        self.merlin.next()
    }

    pub fn squeeze<const N: usize>(&mut self) -> Result<[u8; N], InvalidTag> {
        self.merlin.squeeze()
    }

    pub fn next_scalars<const N: usize>(&mut self) -> Result<[G::ScalarField; N], InvalidTag> {
        self.merlin.next_scalars()
    }

    pub fn public_scalars(&mut self, input: &[G::ScalarField]) -> Result<(), InvalidTag> {
        self.merlin.public_scalars(input)
    }

    pub fn squeeze_scalars<const N: usize>(&mut self) -> Result<[G::ScalarField; N], InvalidTag> {
        self.merlin.squeeze_scalars()
    }

    pub fn next_points<const N: usize>(&mut self) -> Result<[G; N], InvalidTag> {
        let mut output = [G::default(); N];
        let point_size = G::default().compressed_size();
        let mut buf = vec![0u8; point_size];

        for o in output.iter_mut() {
            self.merlin.next_fill(&mut buf)?;
            *o = G::Affine::deserialize_compressed_unchecked(buf.as_slice())
                .expect("Invalid")
                .into();
        }
        Ok(output)
    }

    pub fn public_points(&mut self, input: &[G]) -> Result<(), InvalidTag> {
        let mut buf = Vec::new();
        for i in input {
            i.into_affine()
                .serialize_compressed(&mut buf)
                .expect("Serialization failed");
        }
        self.merlin.public_input(&buf)
    }
}
