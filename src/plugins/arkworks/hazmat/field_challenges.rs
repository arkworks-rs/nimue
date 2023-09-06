use super::super::hash::DuplexHash;
use super::super::{Arthur, InvalidTag, Merlin};
use ark_ff::PrimeField;
use rand::{CryptoRng, RngCore};

pub trait FieldChallenges {
    /// Squeeze a field element challenge of `byte_count` bytes
    /// from the protocol transcript.
    ///
    /// This function provides more control over the number of bytes squeezed by the hash funciton when producing a challenge.
    /// WARNING: the number of bytes often maps directly to the security level desired. A challenge of 16 bytes is often used for 127-bit knowledge soundness.
    fn short_field_challenge<F: PrimeField>(&mut self, byte_count: usize) -> Result<F, InvalidTag>;

    /// Fill a slice of field element challenges of `byte_count` bytes.
    fn field_challenges<F: PrimeField, const N: usize>(&mut self) -> Result<[F; N], InvalidTag> {
        dest.iter_mut()
            .map(|elt| self.field_challenge().and_then(|x| Ok(*elt = x)))
            .collect()
    }

    /// Squeeze a field element challenge uniformly distributed over the whole domain.
    fn field_challenge<F: PrimeField>(&mut self) -> Result<F, InvalidTag> {
        self.short_field_challenge(super::random_felt_bytelen::<F>())
    }
}

impl<S: DuplexHash, R: RngCore + CryptoRng> FieldChallenges for Arthur<S, R> {
    fn short_field_challenge<F: PrimeField>(&mut self, byte_count: usize) -> Result<F, InvalidTag> {
        self.merlin.short_field_challenge(byte_count)
    }
}

impl<S: DuplexHash> FieldChallenges for Merlin<S> {
    /// Get a field element challenge from the protocol transcript.
    ///
    /// The number of random bytes used to generate the challenge is explicit:
    /// commonly implementations choose 16 for 127-bit knowledge soundness,
    /// but larger challenges are supported. To get a challenge uniformly distributed
    /// over the entire field `F`, squeeze F::num_bits()/8 + 100.
    fn short_field_challenge<F: PrimeField>(&mut self, byte_count: usize) -> Result<F, InvalidTag> {
        let mut chal = vec![0u8; byte_count];
        self.squeeze_bytes(&mut chal)?;
        Ok(F::from_le_bytes_mod_order(&chal))
    }
}
