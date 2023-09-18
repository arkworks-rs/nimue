use ark_ec::CurveGroup;
use ark_serialize::CanonicalDeserialize;

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
        for mut o in output.iter_mut() {
            *o = G::ScalarField::deserialize_uncompressed_unchecked(&mut self.transcript)
                .expect("Invalid");
        }
        Ok(output)
    }
    fn absorb_points<const N: usize>(&mut self) -> Result<[G; N], InvalidTag> {
        let mut output = [G::default(); N];
        for mut o in output.iter_mut() {
            *o = G::Affine::deserialize_compressed_unchecked(&mut self.transcript)
                .expect("Invalid")
                .into();
        }
        Ok(output)
    }
    fn squeeze_scalars<const N: usize>(&mut self) -> Result<[G::ScalarField; N], InvalidTag> {
        let mut output = [G::ScalarField::default(); N];
        self.safe.squeeze_scalars(&mut output).map(|()| output)
    }
}
