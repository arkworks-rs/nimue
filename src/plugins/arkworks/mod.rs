mod arthur;
mod iopattern;
mod merlin;

use ark_ff::{Fp, FpConfig, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use std::io;

use crate::ProofError;
pub use crate::{hash::Unit, Arthur, DuplexHash, IOPattern, IOPatternError, Merlin, Safe};
pub use arthur::{ArkFieldArthur, ArkGroupArthur};
pub use iopattern::{ArkFieldIOPattern, ArkGroupIOPattern};
pub use merlin::{ArkFieldMerlin, ArkGroupMerlin};

/// Compute the bits needed in order to obtain a
/// (pseudo-random) uniform distribution in F.
const fn f_bytes<F: PrimeField>() -> usize {
    (F::MODULUS_BIT_SIZE as usize + 128) / 8
}

impl<C: FpConfig<N>, const N: usize> Unit for Fp<C, N> {
    fn write(bunch: &[Self], mut w: &mut impl io::Write) -> Result<(), io::Error> {
        for b in bunch {
            b.serialize_compressed(&mut w)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "oh no!"))?
        }
        Ok(())
    }

    fn read(mut r: &mut impl std::io::Read, bunch: &mut [Self]) -> Result<(), std::io::Error> {
        for b in bunch.iter_mut() {
            *b = ark_ff::Fp::<C, N>::deserialize_compressed(&mut r)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "oh no!"))?
        }
        Ok(())
    }
}

impl From<SerializationError> for ProofError {
    fn from(_value: SerializationError) -> Self {
        ProofError::SerializationError
    }
}
