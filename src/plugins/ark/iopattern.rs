use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use super::*;
use crate::plugins::{bytes_modp, bytes_uniform_modp};

impl<F, H> FieldIOPattern<F> for IOPattern<H>
where
    F: PrimeField,
    H: DuplexHash,
{
    fn add_scalars(self, count: usize, label: &str) -> Self {
        self.add_bytes(count * bytes_modp(F::MODULUS_BIT_SIZE), label)
    }

    fn challenge_scalars(self, count: usize, label: &str) -> Self {
        self.challenge_bytes(count * bytes_uniform_modp(F::MODULUS_BIT_SIZE), label)
    }
}

impl<G, H> GroupIOPattern<G> for IOPattern<H>
where
    G: CurveGroup,
    H: DuplexHash,
{
    fn add_points(self, count: usize, label: &str) -> Self {
        self.add_bytes(count * G::default().compressed_size(), label)
    }
}

#[test]
fn test_iopattern() {
    // OPTION 1 (fails)
    // let io_pattern = IOPattern::new("github.com/mmaker/nimue")
    //     .absorb_points(1, "g")
    //     .absorb_points(1, "pk")
    //     .ratchet()
    //     .absorb_points(1, "com")
    //     .squeeze_scalars(1, "chal")
    //     .absorb_scalars(1, "resp");

    // // OPTION 2
    fn add_schnorr_iopattern<G: ark_ec::CurveGroup, H: DuplexHash<u8>>() -> IOPattern<H, u8>
    where
        IOPattern<H, u8>: GroupIOPattern<G>,
    {
        IOPattern::new("github.com/mmaker/nimue")
            .add_points(1, "g")
            .add_points(1, "pk")
            .ratchet()
            .add_points(1, "com")
            .challenge_scalars(1, "chal")
            .add_scalars(1, "resp")
    }
    let io_pattern =
        add_schnorr_iopattern::<ark_curve25519::EdwardsProjective, crate::DefaultHash>();

    // OPTION 3 (extra type, trait extensions should be on IOPattern or AlgebraicIOPattern?)
    // let io_pattern =
    //     ArkGroupIOPattern::<ark_curve25519::EdwardsProjective>::new("github.com/mmaker/nimue")
    //         .add_points(1, "g")
    //         .add_points(1, "pk")
    //         .ratchet()
    //         .add_points(1, "com")
    //         .challenge_scalars(1, "chal")
    //         .add_scalars(1, "resp");

    assert_eq!(
        io_pattern.as_bytes(),
        b"github.com/mmaker/nimue\0A32g\0A32pk\0R\0A32com\0S47chal\0A32resp"
    )
}
