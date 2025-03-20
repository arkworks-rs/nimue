use crate::{
    VerifierMessageBytes, ByteDomainSeparator, ByteReader, ByteWriter, DefaultHash, DuplexSpongeInterface, DomainSeparator,
    ProofResult, Unit, UnitTranscript,
};

use ark_ff::Field;

/// Test that the algebraic hashes do use the IV generated from the IO Pattern.
fn check_iv_is_used<H: DuplexSpongeInterface<F>, F: Unit + Copy + Default + Eq + core::fmt::Debug>() {
    let io1 = DomainSeparator::<H, F>::new("test").squeeze(1, "out");
    let io2 = DomainSeparator::<H, F>::new("another_test").squeeze(1, "out");

    let [mut merlin1, mut merlin2] = [io1.to_merlin(), io2.to_merlin()];
    let mut c = [F::default(); 2];
    merlin1.fill_challenge_units(&mut c[0..1]).unwrap();
    merlin2.fill_challenge_units(&mut c[1..2]).unwrap();
    assert_ne!(c[0], c[1]);
}

#[test]
fn test_iv_is_used() {
    check_iv_is_used::<DefaultHash, u8>();
}

fn ark_iopattern<F, H>() -> DomainSeparator<H>
where
    F: Field,
    H: DuplexSpongeInterface,
    DomainSeparator<H>: super::FieldDomainSeparator<F> + ByteDomainSeparator,
{
    use super::{ByteDomainSeparator, FieldDomainSeparator};

    DomainSeparator::new("github.com/mmaker/spongefish")
        .add_scalars(3, "com")
        .challenge_bytes(16, "chal")
        .add_bytes(16, "resp")
        .challenge_scalars(2, "chal")
}

fn test_arkworks_end_to_end<F: Field, H: DuplexSpongeInterface>() -> ProofResult<()> {
    use crate::codecs::arkworks_algebra::{UnitToField, DeserializeField, FieldToUnit};
    use rand::Rng;

    let mut rng = ark_std::test_rng();
    // Generate elements for the transcript
    let (f0, f1, f2) = (F::rand(&mut rng), F::rand(&mut rng), F::rand(&mut rng));
    let mut b0 = [0; 16];
    let mut c0 = [0; 16];
    let b1: [u8; 16] = rng.gen();
    let mut f3 = [F::ZERO; 2];
    let mut g3 = [F::ZERO; 2];

    let domain_separator = ark_iopattern::<F, H>();

    let mut merlin = domain_separator.to_merlin();

    merlin.add_scalars(&[f0, f1, f2])?;
    merlin.fill_challenge_bytes(&mut b0)?;
    merlin.add_bytes(&b1)?;
    merlin.fill_challenge_scalars(&mut f3)?;

    let mut arthur = domain_separator.to_verifier_state(merlin.narg_string());
    let [g0, g1, g2]: [F; 3] = arthur.next_scalars()?;
    arthur.fill_challenge_bytes(&mut c0)?;
    let c1: [u8; 16] = arthur.next_bytes()?;
    arthur.fill_challenge_scalars(&mut g3)?;

    assert_eq!(f0, g0);
    assert_eq!(f1, g1);
    assert_eq!(f2, g2);
    assert_eq!(f3, g3);
    assert_eq!(b0, c0);
    assert_eq!(b1, c1);

    Ok(())
}

#[test]
fn test_squeeze_bytes_from_modp() {
    use ark_bls12_381::{Fq, Fr};
    use ark_ff::PrimeField;

    use crate::codecs::random_bytes_in_random_modp;
    let useful_bytes = random_bytes_in_random_modp(Fr::MODULUS);
    assert_eq!(useful_bytes, 127 / 8);

    let useful_bytes = random_bytes_in_random_modp(Fq::MODULUS);
    assert_eq!(useful_bytes, 253 / 8);
}

#[test]
fn test_arkworks() {
    use ark_bls12_381::{Fq2, Fr};
    type F = Fr;
    type F2 = Fq2;

    test_arkworks_end_to_end::<F, DefaultHash>().unwrap();
    test_arkworks_end_to_end::<F2, DefaultHash>().unwrap();
}
