//! This code has been blatantly stolen from `ark-crypto-primitive::sponge`
//! from William Lin, with contributions from Pratyush Mishra, Weikeng Chen, Yuwen Zhang, Kristian Sosnin, Merlyn, Wilson Nguyen, Hossein Moghaddas, and others.
use std::fmt::Debug;

use ark_ff::PrimeField;
use nimue::hash::sponge::DuplexSponge;
use nimue::hash::sponge::Sponge;
use nimue::hash::Unit;

/// Poseidon Sponge.
///
/// The `NAME` const is to distinbuish between different bitsizes of the same Field.
/// For instance Bls12_381 and Bn254 both have field type Fp<MontBackend<FrConfig, 4>, 4> but are different fields.
#[derive(Clone)]
pub struct PoseidonSponge<const NAME: u32, F: PrimeField, const R: usize, const N: usize> {
    /// Number of rounds in a full-round operation.
    pub full_rounds: usize,
    /// Number of rounds in a partial-round operation.
    pub partial_rounds: usize,
    /// Exponent used in S-boxes.
    pub alpha: u64,
    /// Additive Round keys. These are added before each MDS matrix application to make it an affine shift.
    /// They are indexed by `ark[round_num][state_element_index]`
    pub ark: &'static [[F; N]],
    /// Maximally Distance Separating (MDS) Matrix.
    pub mds: &'static [[F; N]],

    /// Sponge state
    pub state: [F; N],
}

pub type PoseidonHash<const NAME: u32, F, const R: usize, const N: usize> =
    DuplexSponge<PoseidonSponge<NAME, F, R, N>>;

impl<const NAME: u32, F: PrimeField, const R: usize, const N: usize> AsRef<[F]>
    for PoseidonSponge<NAME, F, R, N>
{
    fn as_ref(&self) -> &[F] {
        &self.state
    }
}

impl<const NAME: u32, F: PrimeField, const R: usize, const N: usize> AsMut<[F]>
    for PoseidonSponge<NAME, F, R, N>
{
    fn as_mut(&mut self) -> &mut [F] {
        &mut self.state
    }
}

impl<const NAME: u32, F: PrimeField, const R: usize, const N: usize> PoseidonSponge<NAME, F, R, N> {
    fn apply_s_box(&self, state: &mut [F], is_full_round: bool) {
        // Full rounds apply the S Box (x^alpha) to every element of state
        if is_full_round {
            for elem in state {
                *elem = elem.pow([self.alpha]);
            }
        }
        // Partial rounds apply the S Box (x^alpha) to just the first element of state
        else {
            state[0] = state[0].pow([self.alpha]);
        }
    }

    #[inline]
    fn apply_ark(&self, state: &mut [F], round_number: usize) {
        state.iter_mut().enumerate().for_each(|(i, state_elem)| {
            *state_elem += self.ark[round_number][i];
        });
    }

    #[allow(clippy::needless_range_loop)]
    fn apply_mds(&self, state: &mut [F]) {
        let mut new_state = [F::ZERO; N];
        for i in 0..N {
            let mut cur = F::zero();
            for j in 0..N {
                cur += state[j] * self.mds[i][j];
            }
            new_state[i] = cur;
        }
        state.clone_from_slice(&new_state);
    }
}

impl<const NAME: u32, F: PrimeField, const R: usize, const N: usize> zeroize::Zeroize
    for PoseidonSponge<NAME, F, R, N>
{
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

impl<const NAME: u32, F, const R: usize, const N: usize> Sponge for PoseidonSponge<NAME, F, R, N>
where
    PoseidonSponge<NAME, F, R, N>: Default,
    F: PrimeField + Unit,
{
    type U = F;
    const N: usize = N;
    const R: usize = R;

    fn new(iv: [u8; 32]) -> Self {
        assert!(N >= 1);
        let mut sponge = Self::default();
        sponge.state[R] = F::from_be_bytes_mod_order(&iv);
        sponge
    }

    fn permute(&mut self) {
        let full_rounds_over_2 = self.full_rounds / 2;
        let mut state = self.state;
        for i in 0..full_rounds_over_2 {
            self.apply_ark(&mut state, i);
            self.apply_s_box(&mut state, true);
            self.apply_mds(&mut state);
        }

        for i in 0..self.partial_rounds {
            self.apply_ark(&mut state, full_rounds_over_2 + i);
            self.apply_s_box(&mut state, false);
            self.apply_mds(&mut state);
        }

        for i in 0..full_rounds_over_2 {
            self.apply_ark(&mut state, full_rounds_over_2 + self.partial_rounds + i);
            self.apply_s_box(&mut state, true);
            self.apply_mds(&mut state);
        }
        self.state = state;
    }
}

impl<const NAME: u32, F: PrimeField, const R: usize, const N: usize> Debug
    for PoseidonSponge<NAME, F, R, N>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.state.fmt(f)
    }
}

/// Initialization of constants.
#[allow(unused)]
macro_rules! poseidon_sponge {
    ($bits: expr, $name: ident, $path: tt) => {
        pub type $name = crate::PoseidonSponge<$bits, $path::Field, { $path::R }, { $path::N }>;

        impl Default for $name {
            fn default() -> Self {
                let alpha = $path::ALPHA;
                Self {
                    full_rounds: $path::R_F,
                    partial_rounds: $path::R_P,
                    alpha,
                    ark: $path::ARK,
                    mds: $path::MDS,
                    state: [ark_ff::Zero::zero(); $path::N],
                }
            }
        }
    };
}

#[cfg(feature = "bls12-381")]
pub mod bls12_381;

#[cfg(feature = "bn254")]
pub mod bn254;

#[cfg(feature = "solinas")]
pub mod f64;

/// Unit-tests.
#[cfg(test)]
mod tests;
