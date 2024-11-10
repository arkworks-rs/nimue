use nimue::hash::sponge::Sponge;

fn test_vector<H: Sponge>(input: &[H::U], output: &[H::U])
where
    H::U: PartialEq + std::fmt::Debug,
{
    let mut hash = H::new([0; 32]);
    hash.as_mut().clone_from_slice(input);
    hash.permute();
    assert_eq!(hash.as_ref(), output);
}

#[cfg(feature = "bls12-381")]
#[test]
fn test_poseidon_bls12_381() {
    use crate::bls12_381::{PoseidonPermx5_255_3, PoseidonPermx5_255_5};
    use ark_ff::MontFp;
    use nimue::IOPattern;
    use nimue::UnitTranscript;

    type F = ark_bls12_381::Fr;

    let tv_x5_255_3_input: [F; 3] = [
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000001"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000002"),
    ];
    let tv_x5_255_3_output: [F; 3] = [
        MontFp!("0x28ce19420fc246a05553ad1e8c98f5c9d67166be2c18e9e4cb4b4e317dd2a78a"),
        MontFp!("0x51f3e312c95343a896cfd8945ea82ba956c1118ce9b9859b6ea56637b4b1ddc4"),
        MontFp!("0x3b2b69139b235626a0bfb56c9527ae66a7bf486ad8c11c14d1da0c69bbe0f79a"),
    ];
    test_vector::<PoseidonPermx5_255_3>(&tv_x5_255_3_input, &tv_x5_255_3_output);

    let tv_x5_255_5_input: [F; 5] = [
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000001"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000002"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000003"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000004"),
    ];
    let tv_x5_255_5_output: [F; 5] = [
        MontFp!("0x2a918b9c9f9bd7bb509331c81e297b5707f6fc7393dcee1b13901a0b22202e18"),
        MontFp!("0x65ebf8671739eeb11fb217f2d5c5bf4a0c3f210e3f3cd3b08b5db75675d797f7"),
        MontFp!("0x2cc176fc26bc70737a696a9dfd1b636ce360ee76926d182390cdb7459cf585ce"),
        MontFp!("0x4dc4e29d283afd2a491fe6aef122b9a968e74eff05341f3cc23fda1781dcb566"),
        MontFp!("0x03ff622da276830b9451b88b85e6184fd6ae15c8ab3ee25a5667be8592cce3b1"),
    ];
    test_vector::<PoseidonPermx5_255_5>(&tv_x5_255_5_input, &tv_x5_255_5_output);

    // Check that poseidon can indeed be instantiated and doesn't do terribly stupid things like give 0 challenges.
    use crate::bls12_381::Poseidonx5_255_3;
    let io = IOPattern::<Poseidonx5_255_3, F>::new("test")
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

#[cfg(feature = "bn254")]
#[test]
fn test_poseidon_bn254() {
    use crate::bn254::{PoseidonPermx5_254_3, PoseidonPermx5_254_5};
    use ark_ff::MontFp;

    type F = ark_bn254::Fr;

    let tv_x5_254_3_input: [F; 3] = [
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000001"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000002"),
    ];
    let tv_x5_254_3_output: [F; 3] = [
        MontFp!("0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"),
        MontFp!("0x0fca49b798923ab0239de1c9e7a4a9a2210312b6a2f616d18b5a87f9b628ae29"),
        MontFp!("0x0e7ae82e40091e63cbd4f16a6d16310b3729d4b6e138fcf54110e2867045a30c"),
    ];
    test_vector::<PoseidonPermx5_254_3>(&tv_x5_254_3_input, &tv_x5_254_3_output);

    let tv_x5_254_5_input: [F; 5] = [
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000000"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000001"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000002"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000003"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000004"),
    ];
    let tv_x5_254_5_output: [F; 5] = [
        MontFp!("0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465"),
        MontFp!("0x1148aaef609aa338b27dafd89bb98862d8bb2b429aceac47d86206154ffe053d"),
        MontFp!("0x24febb87fed7462e23f6665ff9a0111f4044c38ee1672c1ac6b0637d34f24907"),
        MontFp!("0x0eb08f6d809668a981c186beaf6110060707059576406b248e5d9cf6e78b3d3e"),
        MontFp!("0x07748bc6877c9b82c8b98666ee9d0626ec7f5be4205f79ee8528ef1c4a376fc7"),
    ];
    test_vector::<PoseidonPermx5_254_5>(&tv_x5_254_5_input, &tv_x5_254_5_output);
}
