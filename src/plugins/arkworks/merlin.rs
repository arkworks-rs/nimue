use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{DuplexHash, InvalidTag, Merlin, Safe};

use super::prelude::{ArkMerlin, ArkSafe};

impl<'a, H, G> ArkMerlin<G, u8> for Merlin<'a, H, u8>
where
    H: DuplexHash<u8>,
    G: CurveGroup,
    Safe<H>: ArkSafe<G, u8>,
{
    fn absorb_scalars<const N: usize>(&mut self) -> Result<[G::ScalarField; N], InvalidTag> {
        let mut output = [G::ScalarField::default(); N];
        let point_size = G::ScalarField::default().compressed_size();

        self.safe.absorb_bytes(&self.transcript[..point_size * N])?;
        for o in output.iter_mut() {
            *o = G::ScalarField::deserialize_uncompressed_unchecked(&mut self.transcript)
                .expect("Invalid");
        }
        Ok(output)
    }

    fn absorb_points<const N: usize>(&mut self) -> Result<[G; N], InvalidTag> {
        let mut output = [G::default(); N];
        let point_size = G::default().compressed_size();

        self.safe.absorb_bytes(&self.transcript[..point_size * N])?;

        for o in output.iter_mut() {
            *o = G::Affine::deserialize_compressed_unchecked(&mut self.transcript)
                .expect("Invalid")
                .into();
        }
        Ok(output)
    }

    fn public_scalars(&mut self, input: &[<G>::ScalarField]) -> Result<(), InvalidTag> {
        let mut buf = Vec::new();
        for i in input {
            i.serialize_compressed(&mut buf)
                .expect("Serialization failed");
        }
        self.safe.absorb_bytes(&buf)
    }

    fn public_points(&mut self, input: &[G]) -> Result<(), InvalidTag> {
        let mut buf = Vec::new();
        for i in input {
            i.serialize_compressed(&mut buf)
                .expect("Serialization failed");
        }
        self.safe.absorb_bytes(&buf)
    }

    fn squeeze_scalars<const N: usize>(&mut self) -> Result<[G::ScalarField; N], InvalidTag> {
        let mut output = [G::ScalarField::default(); N];
        self.safe.squeeze_scalars(&mut output).map(|()| output)
    }
}
