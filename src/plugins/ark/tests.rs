#[cfg(feature = "ark-bls12-381")]
use super::poseidon::PoseidonHash;
use crate::{DefaultHash, DuplexHash, IOPattern, Unit, UnitTranscript};
#[cfg(feature = "ark-bls12-381")]
use ark_bls12_381::Fr;

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
