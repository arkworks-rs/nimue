use crate::{DefaultHash, DuplexHash, IOPattern, Unit, UnitTranscript};
use ark_bls12_381::Fr;

use super::poseidon::PoseidonHash;

/// Test that the algebraic hashes do use the IV generated from the IO Pattern.
fn check_iv_is_used<H: DuplexHash<F>, F: Unit + Copy + Default + Eq + core::fmt::Debug>() {
    let io1 = IOPattern::<H, F>::new("test").squeeze(1, "out");
    let io2 = IOPattern::<H, F>::new("another_test").squeeze(1, "out");

    let [mut arthur1, mut arthur2] = [io1.to_arthur(), io2.to_arthur()];
    let mut c = [F::default(); 2];
    arthur1.fill_challenge_units(&mut c[0..1]).unwrap();
    arthur2.fill_challenge_units(&mut c[1..2]).unwrap();
    assert_ne!(c[0], c[1]);
}

#[test]
fn test_iv_is_used() {
    check_iv_is_used::<DefaultHash, u8>();
    check_iv_is_used::<PoseidonHash<Fr, 2, 3>, Fr>();
}

/// Check that poseidon can indeed be instantiated and doesn't do terribly stupid things like give 0 challenges.
#[test]
fn test_poseidon_basic() {
    type F = Fr;
    type H = PoseidonHash<F, 2, 3>;

    let io = IOPattern::<H, F>::new("test")
        .absorb(1, "in")
        .squeeze(10, "out");
    let mut arthur = io.to_arthur();
    arthur.add_units(&[F::from(0x42)]).unwrap();

    let mut challenges = [F::from(0); 10];
    arthur.fill_challenge_units(&mut challenges).unwrap();

    for challenge in challenges {
        assert_ne!(challenge, F::from(0));
    }
}
