use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use rand::{CryptoRng, RngCore};

use super::prelude::*;

impl<H, G, R> ArkArthur<G, u8> for Arthur<H, R, u8>
where
    H: DuplexHash<u8>,
    G: CurveGroup,
    R: RngCore + CryptoRng,
{
    fn absorb_scalars(&mut self, input: &[G::ScalarField]) -> Result<(), InvalidTag> {
        let old_len = self.transcript.len();
        for scalar in input {
            scalar
                .serialize_compressed(&mut self.transcript)
                .expect("serialization failed");
        }
        let serialized = &self.transcript[old_len..];
        self.rng.sponge.absorb_unchecked(serialized);
        self.safe.absorb_bytes(serialized)
    }

    fn absorb_points(&mut self, input: &[G]) -> Result<(), InvalidTag> {
        let old_len = self.transcript.len();
        for point in input {
            point
                .serialize_compressed(&mut self.transcript)
                .expect("serialization failed");
        }
        let serialized = &self.transcript[old_len..];
        self.rng.sponge.absorb_unchecked(serialized);
        self.safe.absorb_bytes(serialized)
    }

    fn squeeze_scalars<const N: usize>(&mut self) -> Result<[G::ScalarField; N], InvalidTag> {
        let mut buf = vec![0u8; super::f_bytes::<G::ScalarField>()];
        let mut output = [G::ScalarField::default(); N];
        for mut o in output.iter_mut() {
            self.safe.squeeze(&mut buf)?;
            *o = G::ScalarField::from_le_bytes_mod_order(&buf);
        }
        Ok(output)
    }
}
