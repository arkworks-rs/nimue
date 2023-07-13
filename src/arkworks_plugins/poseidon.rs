use super::{DuplexSponge, Lane, SpongeConfig};
use crate::sponge::{
    poseidon::{PoseidonConfig, PoseidonDefaultConfigField, PoseidonSponge},
    CryptographicSponge,
};

use ark_std::UniformRand;

impl<F: Lane + PoseidonDefaultConfigField> SpongeConfig for PoseidonSponge<F> {
    type L = F;

    fn new() -> Self {
        /// XXX. the rate should be set by the user with a macro that implements this trait.
        let config = F::get_default_poseidon_parameters(2, false).unwrap();
        <Self as CryptographicSponge>::new(&config)
    }

    fn capacity(&self) -> usize {
        self.parameters.capacity
    }

    fn rate(&self) -> usize {
        self.parameters.rate
    }

    fn permute(&mut self, state: &mut [Self::L]) {
        self.state.clone_from_slice(&state);
        self.permute();
        state.clone_from_slice(&mut self.state)
    }
}

pub type PoseidonSpongeNG<F> = DuplexSponge<PoseidonSponge<F>>;