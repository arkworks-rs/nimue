#[cfg(feature = "ark-bls12-381")]
use super::poseidon::PoseidonHash;
use crate::{
    ByteChallenges, ByteIOPattern, ByteReader, ByteWriter, DefaultHash, DuplexHash, IOPattern,
    ProofResult, Unit, UnitTranscript,
};
#[cfg(feature = "ark-bls12-381")]
use ark_bls12_381::{Fq2, Fr};
use ark_ff::Field;

/// Test that the algebraic hashes do use the IV generated from the IO Pattern.
fn check_iv_is_used<H: DuplexHash<F>, F: Unit + Copy + Default + Eq + core::fmt::Debug>() {
    let io1 = IOPattern::<H, F>::new("test").squeeze(1, "out");
    let io2 = IOPattern::<H, F>::new("another_test").squeeze(1, "out");

    let [mut merlin1, mut merlin2] = [io1.to_merlin(), io2.to_merlin()];
    let mut c = [F::default(); 2];
    merlin1.fill_challenge_units(&mut c[0..1]).unwrap();
    merlin2.fill_challenge_units(&mut c[1..2]).unwrap();
    assert_ne!(c[0], c[1]);
}

#[test]
fn test_iv_is_used() {
    check_iv_is_used::<DefaultHash, u8>();
    #[cfg(feature = "ark-bls12-381")]
    check_iv_is_used::<PoseidonHash<Fr, 2, 3>, Fr>();
}

/// Check that poseidon can indeed be instantiated and doesn't do terribly stupid things like give 0 challenges.
#[test]
#[cfg(feature = "ark-bls12-381")]
fn test_poseidon_basic() {
    type F = Fr;
    type H = PoseidonHash<F, 2, 3>;

    let io = IOPattern::<H, F>::new("test")
        .absorb(1, "in")
        .squeeze(10, "out");
    let mut merlin = io.to_merlin();
    merlin.add_units(&[F::from(0x42)]).unwrap();

    let mut challenges = [F::from(0); 10];
    merlin.fill_challenge_units(&mut challenges).unwrap();

    for challenge in challenges {
        assert_ne!(challenge, F::from(0));
    }
}

fn ark_iopattern<F, H>() -> IOPattern<H>
where
    F: Field,
    H: DuplexHash,
    IOPattern<H>: super::FieldIOPattern<F> + ByteIOPattern,
{
    use super::{ByteIOPattern, FieldIOPattern};

    IOPattern::new("github.com/mmaker/nimue")
        .add_scalars(3, "com")
        .challenge_bytes(16, "chal")
        .add_bytes(16, "resp")
        .challenge_scalars(2, "chal")
}

fn test_arkworks_end_to_end<F: Field, H: DuplexHash>() -> ProofResult<()> {
    use crate::plugins::ark::{FieldChallenges, FieldReader, FieldWriter};
    use rand::Rng;

    let mut rng = ark_std::test_rng();
    // Generate elements for the transcript
    let (f0, f1, f2) = (F::rand(&mut rng), F::rand(&mut rng), F::rand(&mut rng));
    let mut b0 = [0; 16];
    let mut c0 = [0; 16];
    let b1: [u8; 16] = rng.gen();
    let mut f3 = [F::ZERO; 2];
    let mut g3 = [F::ZERO; 2];

    let io_pattern = ark_iopattern::<F, H>();

    let mut merlin = io_pattern.to_merlin();

    merlin.add_scalars(&[f0, f1, f2])?;
    merlin.fill_challenge_bytes(&mut b0)?;
    merlin.add_bytes(&b1)?;
    merlin.fill_challenge_scalars(&mut f3)?;

    let mut arthur = io_pattern.to_arthur(merlin.transcript());
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

#[cfg(feature = "ark-bls12-381")]
#[test]
fn test_arkworks() {
    type F = Fr;
    type F2 = Fq2;

    test_arkworks_end_to_end::<F, DefaultHash>().unwrap();
    test_arkworks_end_to_end::<F2, DefaultHash>().unwrap();
}
