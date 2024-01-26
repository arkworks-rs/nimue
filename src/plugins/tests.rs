use ark_ec::PrimeGroup;
use ark_serialize::CanonicalSerialize;
use group::{Group, GroupEncoding};

use crate::hash::Keccak;
use crate::{plugins, ByteIOPattern};
use crate::{ByteTranscript, DuplexHash, IOPattern};

fn group_iopattern<G, H>() -> IOPattern<H>
where
    G: group::Group,
    H: DuplexHash,
    IOPattern<H>: super::group::GroupIOPattern<G>,
{
    use plugins::group::{FieldIOPattern, GroupIOPattern};

    IOPattern::new("github.com/mmaker/nimue")
        .add_scalars(1, "com")
        .challenge_bytes(16, "chal")
        .add_points(1, "com")
        .challenge_bytes(16, "chal")
        .challenge_scalars(1, "chal")
}

fn ark_iopattern<G, H>() -> IOPattern<H>
where
    G: ark_ec::CurveGroup,
    H: DuplexHash,
    IOPattern<H>: super::ark::GroupIOPattern<G>,
{
    use plugins::ark::{FieldIOPattern, GroupIOPattern};

    IOPattern::new("github.com/mmaker/nimue")
        .add_scalars(1, "com")
        .challenge_bytes(16, "chal")
        .add_points(1, "com")
        .challenge_bytes(16, "chal")
        .challenge_scalars(1, "chal")
}

// Check that the transcripts generated using the Group trait can be compatible with transcripts generated using dalek.
#[test]
fn test_compatible_ark_dalek() {
    type ArkG = ark_curve25519::EdwardsProjective;
    type ArkF = ark_curve25519::Fr;

    type GroupG = curve25519_dalek::edwards::EdwardsPoint;
    type GroupF = curve25519_dalek::scalar::Scalar;
    let ark_scalar = ArkF::from(0x42);
    let dalek_scalar = GroupF::from(0x42u64);
    // ***IMPORTANT***
    // Looks like dalek and arkworks use different generator points.
    let ark_generator = ArkG::generator();
    let dalek_generator = -GroupG::generator();

    // **basic checks**
    // Check point encoding is the same in both libraries.
    let mut ark_generator_bytes = Vec::new();
    ark_generator
        .serialize_compressed(&mut ark_generator_bytes)
        .unwrap();
    let dalek_generator_bytes = <GroupG as GroupEncoding>::to_bytes(&dalek_generator);
    assert_eq!(&ark_generator_bytes, &dalek_generator_bytes);
    // Check scalar encoding is the same in both libraries.
    let mut ark_scalar_bytes = Vec::new();
    ark_scalar
        .serialize_compressed(&mut ark_scalar_bytes)
        .unwrap();
    let dalek_scalar_bytes = dalek_scalar.to_bytes();
    assert_eq!(&ark_scalar_bytes, &dalek_scalar_bytes);

    let ark_point = ark_generator * ark_scalar;
    let dalek_point = dalek_generator * dalek_scalar;

    let ark_io = ark_iopattern::<ArkG, Keccak>();
    let dalek_io = group_iopattern::<GroupG, Keccak>();
    let mut ark_chal = [0u8; 16];
    let mut dalek_chal = [0u8; 16];

    // Check that the IO Patterns are the same.
    let mut ark_prover = ark_io.to_arthur();
    let mut dalek_prover = dalek_io.to_arthur();
    assert_eq!(ark_io.as_bytes(), dalek_io.as_bytes());

    // Check that scalars absorption leads to the same transcript.
    plugins::ark::FieldWriter::add_scalars(&mut ark_prover, &[ark_scalar]).unwrap();
    ark_prover.fill_challenge_bytes(&mut ark_chal).unwrap();
    plugins::group::FieldWriter::add_scalars(&mut dalek_prover, &[dalek_scalar]).unwrap();
    dalek_prover.fill_challenge_bytes(&mut dalek_chal).unwrap();
    assert_eq!(ark_chal, dalek_chal);

    // Check that points absorption leads to the same transcript.
    plugins::ark::GroupWriter::add_points(&mut ark_prover, &[ark_point]).unwrap();
    ark_prover.fill_challenge_bytes(&mut ark_chal).unwrap();
    plugins::group::GroupWriter::add_points(&mut dalek_prover, &[dalek_point]).unwrap();
    dalek_prover.fill_challenge_bytes(&mut dalek_chal).unwrap();
    assert_eq!(ark_chal, dalek_chal);

    // Check that scalars challenges are interpreted in the same way from bytes.
    let [ark_chal_scalar]: [ArkF; 1] =
        plugins::ark::FieldChallenges::challenge_scalars(&mut ark_prover).unwrap();
    let [dalek_chal_scalar]: [GroupF; 1] =
        plugins::group::FieldChallenges::challenge_scalars(&mut dalek_prover).unwrap();
    let mut ark_scalar_bytes = Vec::new();
    ark_chal_scalar
        .serialize_compressed(&mut ark_scalar_bytes)
        .unwrap();
    let dalek_scalar_bytes = dalek_chal_scalar.to_bytes();
    assert_eq!(&ark_scalar_bytes, &dalek_scalar_bytes);
}
