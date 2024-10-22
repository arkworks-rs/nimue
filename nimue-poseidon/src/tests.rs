use crate::PoseidonHash;
use ark_bls12_381::Fr;
use nimue::IOPattern;
use nimue::UnitTranscript;

/// Check that poseidon can indeed be instantiated and doesn't do terribly stupid things like give 0 challenges.
#[test]
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
