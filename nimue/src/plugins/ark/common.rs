use std::io;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, Fp, FpConfig, PrimeField};
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
    F: Field,
    T: UnitTranscript<u8>,
{
    fn fill_challenge_scalars(&mut self, output: &mut [F]) -> ProofResult<()> {
        let base_field_size = bytes_uniform_modp(F::BasePrimeField::MODULUS_BIT_SIZE);
        let mut buf = vec![0u8; F::extension_degree() as usize * base_field_size];

        for o in output.iter_mut() {
            self.fill_challenge_bytes(&mut buf)?;
            *o = F::from_base_prime_field_elems(
                buf.chunks(base_field_size)
                    .map(F::BasePrimeField::from_be_bytes_mod_order),
            )
            .expect("Could not convert");
        }
        Ok(())
    }
}

impl<H, C, const N: usize> FieldChallenges<Fp<C, N>> for Arthur<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexHash<Fp<C, N>>,
{
    fn fill_challenge_scalars(&mut self, output: &mut [Fp<C, N>]) -> ProofResult<()> {
        self.fill_challenge_units(output)
            .map_err(ProofError::InvalidIO)
    }
}

impl<H, C, R, const N: usize> FieldChallenges<Fp<C, N>> for Merlin<H, Fp<C, N>, R>
where
    C: FpConfig<N>,
    H: DuplexHash<Fp<C, N>>,
    R: CryptoRng + RngCore,
{
    fn fill_challenge_scalars(&mut self, output: &mut [Fp<C, N>]) -> ProofResult<()> {
        self.fill_challenge_units(output)
            .map_err(ProofError::InvalidIO)
    }
}

// Field <-> Field interactions:

impl<F, H, R, C, const N: usize> FieldPublic<F> for Merlin<H, Fp<C, N>, R>
where
    F: Field<BasePrimeField = Fp<C, N>>,
    H: DuplexHash<Fp<C, N>>,
    R: RngCore + CryptoRng,
    C: FpConfig<N>,
{
    type Repr = ();

    fn public_scalars(&mut self, input: &[F]) -> ProofResult<Self::Repr> {
        let flattened: Vec<_> = input
            .iter()
            .flat_map(|f| f.to_base_prime_field_elements())
            .collect();
        self.public_units(&flattened)?;
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

impl<F, H, C, const N: usize> FieldPublic<F> for Arthur<'_, H, Fp<C, N>>
where
    F: Field<BasePrimeField = Fp<C, N>>,
    H: DuplexHash<Fp<C, N>>,
    C: FpConfig<N>,
{
    type Repr = ();

    fn public_scalars(&mut self, input: &[F]) -> ProofResult<Self::Repr> {
        let flattened: Vec<_> = input
            .iter()
            .flat_map(|f| f.to_base_prime_field_elements())
            .collect();
        self.public_units(&flattened)?;
        Ok(())
    }
}

impl<H, R, C, const N: usize, G> GroupPublic<G> for Merlin<H, Fp<C, N>, R>
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

impl<H, C, const N: usize, G> GroupPublic<G> for Arthur<'_, H, Fp<C, N>>
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

impl<H, C, const N: usize> BytePublic for Arthur<'_, H, Fp<C, N>>
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

impl<H, R, C, const N: usize> BytePublic for Merlin<H, Fp<C, N>, R>
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

impl<H, R, C, const N: usize> ByteChallenges for Merlin<H, Fp<C, N>, R>
where
    C: FpConfig<N>,
    H: DuplexHash<Fp<C, N>>,
    R: CryptoRng + RngCore,
{
    fn fill_challenge_bytes(&mut self, output: &mut [u8]) -> Result<(), IOPatternError> {
        if output.is_empty() {
            Ok(())
        } else {
            let len_good = usize::min(
                crate::plugins::random_bytes_in_random_modp(Fp::<C, N>::MODULUS),
                output.len(),
            );
            let mut tmp = [Fp::from(0); 1];
            self.fill_challenge_units(&mut tmp)?;
            let buf = tmp[0].into_bigint().to_bytes_le();
            output[..len_good].copy_from_slice(&buf[..len_good]);

            // recursively fill the rest of the buffer
            self.fill_challenge_bytes(&mut output[len_good..])
        }
    }
}

/// XXX. duplicate code
impl<H, C, const N: usize> ByteChallenges for Arthur<'_, H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexHash<Fp<C, N>>,
{
    fn fill_challenge_bytes(&mut self, output: &mut [u8]) -> Result<(), IOPatternError> {
        if output.is_empty() {
            Ok(())
        } else {
            let len_good = usize::min(
                crate::plugins::random_bytes_in_random_modp(Fp::<C, N>::MODULUS),
                output.len(),
            );
            let mut tmp = [Fp::from(0); 1];
            self.fill_challenge_units(&mut tmp)?;
            let buf = tmp[0].into_bigint().to_bytes_le();
            output[..len_good].copy_from_slice(&buf[..len_good]);

            // recursively fill the rest of the buffer
            self.fill_challenge_bytes(&mut output[len_good..])
        }
    }
}
