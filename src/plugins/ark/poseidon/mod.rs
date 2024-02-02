//! This code has been blatantly stolen from `ark-crypto-primitive::sponge`
//! from William Lin, with contributions from Pratyush Mishra, Weikeng Chen, Yuwen Zhang, Kristian Sosnin, Merlyn, Wilson Nguyen, Hossein Moghaddas, and others.
use ark_ff::PrimeField;

use crate::hash::sponge::Sponge;
use crate::hash::Unit;

#[derive(Clone)]
pub struct PoseidonSponge<F: PrimeField, const R: usize, const N: usize> {
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

pub type PoseidonHash<F, const R: usize, const N: usize> = crate::hash::sponge::DuplexSponge<PoseidonSponge<F, R, N>>;


impl<F: PrimeField, const R: usize, const N: usize> AsRef<[F]> for PoseidonSponge<F, R, N> {
    fn as_ref(&self) -> &[F] {
        &self.state
    }
}

impl<F: PrimeField, const R: usize, const N: usize> AsMut<[F]> for PoseidonSponge<F, R, N> {
    fn as_mut(&mut self) -> &mut [F] {
        &mut self.state
    }
}

impl<F: PrimeField, const R: usize, const N: usize> PoseidonSponge<F, R, N> {
    fn apply_s_box(&self, state: &mut [F], is_full_round: bool) {
        // Full rounds apply the S Box (x^alpha) to every element of state
        if is_full_round {
            for elem in state {
                *elem = elem.pow(&[self.alpha]);
            }
        }
        // Partial rounds apply the S Box (x^alpha) to just the first element of state
        else {
            state[0] = state[0].pow(&[self.alpha]);
        }
    }

    fn apply_ark(&self, state: &mut [F], round_number: usize) {
        for (i, state_elem) in state.iter_mut().enumerate() {
            state_elem.add_assign(&self.ark[round_number][i]);
        }
    }

    fn apply_mds(&self, state: &mut [F]) {
        let mut new_state = Vec::new();
        for i in 0..state.len() {
            let mut cur = F::zero();
            for (j, &state_elem) in state.iter().enumerate() {
                let term = state_elem * self.mds[i][j];
                cur.add_assign(&term);
            }
            new_state.push(cur);
        }
        state.clone_from_slice(&new_state[..state.len()])
    }
}

impl<F: PrimeField, const R: usize, const N: usize> zeroize::Zeroize for PoseidonSponge<F, R, N> {
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

impl<F, const R: usize, const N: usize> Sponge for PoseidonSponge<F, R, N>
where
    PoseidonSponge<F, R, N>: Default,
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
        let mut state = self.state.clone();
        for i in 0..full_rounds_over_2 {
            self.apply_ark(&mut state, i);
            self.apply_s_box(&mut state, true);
            self.apply_mds(&mut state);
        }

        for i in full_rounds_over_2..(full_rounds_over_2 + self.partial_rounds) {
            self.apply_ark(&mut state, i);
            self.apply_s_box(&mut state, false);
            self.apply_mds(&mut state);
        }

        for i in
            (full_rounds_over_2 + self.partial_rounds)..(self.partial_rounds + self.full_rounds)
        {
            self.apply_ark(&mut state, i);
            self.apply_s_box(&mut state, true);
            self.apply_mds(&mut state);
        }
        self.state = state;
    }
}

/// Initialization of constants.
macro_rules! poseidon_sponge {
    ($name: ident, $path: tt) => {
        pub type $name = crate::hash::sponge::DuplexSponge<poseidon::PoseidonSponge< $path::Field, {$path::R}, {$path::N} >>;

        impl Default for poseidon::PoseidonSponge< $path::Field, {$path::R}, {$path::N} > {
            fn default() -> Self {
                let alpha = $path::ALPHA;
                let full_rounds = $path::FULL_ROUNDS;
                let total_rounds = $path::TOTAL_ROUNDS;
                let partial_rounds = total_rounds - full_rounds;
                Self {
                    full_rounds,
                    partial_rounds,
                    alpha,
                    ark: $path::ARK,
                    mds: $path::MDS,
                    state: [ark_ff::Zero::zero(); $path::N],
                }
            }
        }
    }
}

#[cfg(feature = "ark-bls12-381")]
pub mod bls12_381;
