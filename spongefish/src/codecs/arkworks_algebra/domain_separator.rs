use ark_ec::CurveGroup;
use ark_ff::{Field, Fp, FpConfig, PrimeField};

use super::*;
use crate::codecs::{bytes_modp, bytes_uniform_modp};

impl<F, H> FieldDomainSeparator<F> for DomainSeparator<H>
where
    F: Field,
    H: DuplexSpongeInterface,
{
    fn add_scalars(self, count: usize, label: &str) -> Self {
        self.add_bytes(
            count
                * F::extension_degree() as usize
                * bytes_modp(F::BasePrimeField::MODULUS_BIT_SIZE),
            label,
        )
    }

    fn challenge_scalars(self, count: usize, label: &str) -> Self {
        self.challenge_bytes(
            count
                * F::extension_degree() as usize
                * bytes_uniform_modp(F::BasePrimeField::MODULUS_BIT_SIZE),
            label,
        )
    }
}

impl<F, C, H, const N: usize> FieldDomainSeparator<F> for DomainSeparator<H, Fp<C, N>>
where
    F: Field<BasePrimeField = Fp<C, N>>,
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    fn add_scalars(self, count: usize, label: &str) -> Self {
        self.absorb(count * F::extension_degree() as usize, label)
    }

    fn challenge_scalars(self, count: usize, label: &str) -> Self {
        self.squeeze(count * F::extension_degree() as usize, label)
    }
}

impl<C, H, const N: usize> ByteDomainSeparator for DomainSeparator<H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    /// Add `count` bytes to the transcript, encoding each of them as an element of the field `Fp`.
    fn add_bytes(self, count: usize, label: &str) -> Self {
        self.absorb(count, label)
    }

    fn challenge_bytes(self, count: usize, label: &str) -> Self {
        let n = crate::codecs::random_bits_in_random_modp(Fp::<C, N>::MODULUS) / 8;
        self.squeeze(count.div_ceil(n), label)
    }
}

impl<G, H> GroupDomainSeparator<G> for DomainSeparator<H>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
{
    fn add_points(self, count: usize, label: &str) -> Self {
        self.add_bytes(count * G::default().compressed_size(), label)
    }
}

impl<G, H, C, const N: usize> GroupDomainSeparator<G> for DomainSeparator<H, Fp<C, N>>
where
    G: CurveGroup<BaseField = Fp<C, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    C: FpConfig<N>,
    DomainSeparator<H, Fp<C, N>>: FieldDomainSeparator<Fp<C, N>>,
{
    fn add_points(self, count: usize, label: &str) -> Self {
        self.absorb(count * 2, label)
    }
}

#[test]
fn test_domain_separator() {
    // OPTION 1 (fails)
    // let domain_separator = DomainSeparator::new("github.com/mmaker/spongefish")
    //     .absorb_points(1, "g")
    //     .absorb_points(1, "pk")
    //     .ratchet()
    //     .absorb_points(1, "com")
    //     .squeeze_scalars(1, "chal")
    //     .absorb_scalars(1, "resp");

    // // OPTION 2
    fn add_schnorr_domain_separator<G: ark_ec::CurveGroup, H: DuplexSpongeInterface<u8>>() -> DomainSeparator<H, u8>
    where
        DomainSeparator<H, u8>: GroupDomainSeparator<G> + FieldDomainSeparator<G::ScalarField>,
    {
        DomainSeparator::new("github.com/mmaker/spongefish")
            .add_points(1, "g")
            .add_points(1, "pk")
            .ratchet()
            .add_points(1, "com")
            .challenge_scalars(1, "chal")
            .add_scalars(1, "resp")
    }
    let domain_separator =
        add_schnorr_domain_separator::<ark_curve25519::EdwardsProjective, crate::DefaultHash>();

    // OPTION 3 (extra type, trait extensions should be on DomainSeparator or AlgebraicDomainSeparator?)
    // let domain_separator =
    //     ArkGroupDomainSeparator::<ark_curve25519::EdwardsProjective>::new("github.com/mmaker/spongefish")
    //         .add_points(1, "g")
    //         .add_points(1, "pk")
    //         .ratchet()
    //         .add_points(1, "com")
    //         .challenge_scalars(1, "chal")
    //         .add_scalars(1, "resp");

    assert_eq!(
        domain_separator.as_bytes(),
        b"github.com/mmaker/spongefish\0A32g\0A32pk\0R\0A32com\0S47chal\0A32resp"
    )
}
