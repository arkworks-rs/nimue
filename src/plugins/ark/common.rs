use std::io;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, Fp, FpConfig, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use rand::{CryptoRng, RngCore};

use super::{FieldChallenges, FieldPublic, GroupPublic};
use crate::plugins::bytes_uniform_modp;
use crate::{
    Arthur, ByteChallenges, BytePublic, DuplexHash, IOPatternError, Merlin, ProofError,
    ProofResult, Unit, UnitTranscript,
};

// Implementation of basic traits for bridging arkworks and nimue

impl<C: FpConfig<N>, const N: usize> Unit for Fp<C, N> {
    fn write(bunch: &[Self], mut w: &mut impl io::Write) -> Result<(), io::Error> {
        for b in bunch {
            b.serialize_compressed(&mut w)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "oh no!"))?
        }
        Ok(())
    }

    fn read(mut r: &mut impl io::Read, bunch: &mut [Self]) -> Result<(), io::Error> {
        for b in bunch.iter_mut() {
            let b_result = Fp::deserialize_compressed(&mut r);
            *b = b_result.map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "Unable to deserialize into Field.")
            })?
        }
        Ok(())
    }
}

impl From<SerializationError> for ProofError {
    fn from(_value: SerializationError) -> Self {
        ProofError::SerializationError
    }
}

// Bytes <-> Field elements interactions:

impl<T, G> GroupPublic<G> for T
where
    G: CurveGroup,
    T: UnitTranscript<u8>,
{
    type Repr = Vec<u8>;

    fn public_points(&mut self, input: &[G]) -> ProofResult<Self::Repr> {
        let mut buf = Vec::new();
        for i in input {
            i.serialize_compressed(&mut buf)?;
        }
        Ok(self.public_bytes(&buf).map(|()| buf)?)
    }
}

impl<T, F> FieldPublic<F> for T
where
    F: Field,
    T: UnitTranscript<u8>,
{
    type Repr = Vec<u8>;

    fn public_scalars(&mut self, input: &[F]) -> ProofResult<Self::Repr> {
        let mut buf = Vec::new();
        for i in input {
            i.serialize_compressed(&mut buf)?;
        }
        self.public_bytes(&buf)?;
        Ok(buf)
    }
}

impl<F, T> FieldChallenges<F> for T
where
    F: PrimeField,
    T: ByteChallenges,
{
    fn fill_challenge_scalars(&mut self, output: &mut [F]) -> ProofResult<()> {
        let mut buf = vec![0u8; bytes_uniform_modp(F::MODULUS_BIT_SIZE)];

        for o in output.iter_mut() {
            self.fill_challenge_bytes(&mut buf)?;
            *o = F::from_be_bytes_mod_order(&buf).into();
        }
        Ok(())
    }
}

// Field <-> Field interactions:

impl<H, R, C, const N: usize> FieldPublic<Fp<C, N>> for Arthur<H, Fp<C, N>, R>
where
    H: DuplexHash<Fp<C, N>>,
    R: RngCore + CryptoRng,
    C: FpConfig<N>,
{
    type Repr = ();

    fn public_scalars(&mut self, input: &[Fp<C, N>]) -> ProofResult<Self::Repr> {
        self.public_units(input)?;
        Ok(())
    }
}

// In a glorious future, we will have this generic implementation working without this error:
// error[E0119]: conflicting implementations of trait `ark::GroupPublic<_>`
//    --> src/plugins/ark/common.rs:121:1
//     |
// 43  | / impl<T, G> GroupPublic<G> for T
// 44  | | where
// 45  | |     G: CurveGroup,
// 46  | |     T: UnitTranscript<u8>,
//     | |__________________________- first implementation here
// ...
// 121 | / impl< C, const N: usize, G, T> GroupPublic<G> for T
// 122 | | where
// 123 | |     T: UnitTranscript<Fp<C, N>>,
// 124 | |     C: FpConfig<N>,
// 125 | |     G: CurveGroup<BaseField = Fp<C, N>>,
//     | |________________________________________^ conflicting implementation
//
//

impl<H, C, const N: usize> FieldPublic<Fp<C, N>> for Merlin<'_, H, Fp<C, N>>
where
    H: DuplexHash<Fp<C, N>>,
    C: FpConfig<N>,
{
    type Repr = ();

    fn public_scalars(&mut self, input: &[Fp<C, N>]) -> ProofResult<Self::Repr> {
        self.public_units(input)?;
        Ok(())
    }
}

impl<H, R, C, const N: usize, G> GroupPublic<G> for Arthur<H, Fp<C, N>, R>
where
    C: FpConfig<N>,
    R: RngCore + CryptoRng,
    H: DuplexHash<Fp<C, N>>,
    G: CurveGroup<BaseField = Fp<C, N>>,
{
    type Repr = ();

    fn public_points(&mut self, input: &[G]) -> ProofResult<Self::Repr> {
        for point in input {
            let (x, y) = point.into_affine().xy().unwrap();
            self.public_units(&[x, y])?;
        }
        Ok(())
    }
}

impl<H, C, const N: usize, G> GroupPublic<G> for Merlin<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexHash<Fp<C, N>>,
    G: CurveGroup<BaseField = Fp<C, N>>,
{
    type Repr = ();

    fn public_points(&mut self, input: &[G]) -> ProofResult<Self::Repr> {
        for point in input {
            let (x, y) = point.into_affine().xy().unwrap();
            self.public_units(&[x, y])?;
        }
        Ok(())
    }
}

// Field  <-> Bytes interactions:

impl<'a, H, C, const N: usize> BytePublic for Merlin<'a, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexHash<Fp<C, N>>,
{
    fn public_bytes(&mut self, input: &[u8]) -> Result<(), IOPatternError> {
        for &byte in input {
            self.public_units(&[Fp::from(byte)])?;
        }
        Ok(())
    }
}

impl<'a, H, R, C, const N: usize> BytePublic for Arthur<H, Fp<C, N>, R>
where
    C: FpConfig<N>,
    H: DuplexHash<Fp<C, N>>,
    R: CryptoRng + rand::RngCore,
{
    fn public_bytes(&mut self, input: &[u8]) -> Result<(), IOPatternError> {
        for &byte in input {
            self.public_units(&[Fp::from(byte)])?;
        }
        Ok(())
    }
}

impl<'a, H, R, C, const N: usize> ByteChallenges for Arthur<H, Fp<C, N>, R>
where
    C: FpConfig<N>,
    H: DuplexHash<Fp<C, N>>,
    R: CryptoRng + rand::RngCore,
{
    fn fill_challenge_bytes(&mut self, output: &mut [u8]) -> Result<(), IOPatternError> {
        let len_good = usize::min(
            crate::plugins::bytes_uniform_modp(Fp::<C, N>::MODULUS_BIT_SIZE),
            output.len(),
        );
        let len = crate::plugins::bytes_modp(Fp::<C, N>::MODULUS_BIT_SIZE);
        let mut tmp = [Fp::from(0); 1];
        let mut buf = vec![0u8; len];
        self.fill_challenge_units(&mut tmp)?;
        tmp[0].serialize_compressed(&mut buf).unwrap();

        output[..len_good].copy_from_slice(&buf[..len_good]);
        Ok(())
    }
}

impl<'a, H, C, const N: usize> ByteChallenges for Merlin<'a, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexHash<Fp<C, N>>,
{
    fn fill_challenge_bytes(&mut self, output: &mut [u8]) -> Result<(), IOPatternError> {
        let len_good = usize::min(
            crate::plugins::bytes_uniform_modp(Fp::<C, N>::MODULUS_BIT_SIZE),
            output.len(),
        );
        let len = crate::plugins::bytes_modp(Fp::<C, N>::MODULUS_BIT_SIZE);
        let mut tmp = [Fp::from(0); 1];
        let mut buf = vec![0u8; len];
        self.fill_challenge_units(&mut tmp)?;
        tmp[0].serialize_compressed(&mut buf).unwrap();

        output[..len_good].copy_from_slice(&buf[..len_good]);
        Ok(())
    }
}
