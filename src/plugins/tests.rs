use crate::hash::Keccak;
use crate::plugins;
use crate::{ByteTranscript, DuplexHash, IOPattern};

fn group_iopattern<G, H>() -> IOPattern<H>
where
    G: group::Group,
    H: DuplexHash,
    IOPattern<H>: super::group::GroupIOPattern<G>,
{
    use plugins::group::{FieldIOPattern, GroupIOPattern};

    IOPattern::new("github.com/mmaker/nimue")
        .add_points(1, "com")
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
        .add_points(1, "com")
        .challenge_scalars(1, "chal")
}

/// Compatibility betweek arkworks and dalek can only be tested when handling scalars.
/// In fact, arkworks does not yet implement ristretto points as per `curve25519_dalek::ristretto::Ristretto`
#[test]
fn test_compatible_ark_dalek() {
    type ArkG = ark_curve25519::EdwardsProjective;
    type ArkF = ark_curve25519::Fr;

    type GroupG = curve25519_dalek::edwards::EdwardsPoint;
    type GroupF = curve25519_dalek::scalar::Scalar;
    let ark_scalar = ArkF::from(0x42);
    let dalek_scalar = GroupF::from(0x42u64);

    let ark_io = ark_iopattern::<ArkG, Keccak>();
    let dalek_io = group_iopattern::<GroupG, Keccak>();

    assert_eq!(ark_io.as_bytes(), dalek_io.as_bytes());

    let mut ark_challenges = [0u8; 16];
    let mut ark_prover = ark_io.to_arthur();
    plugins::ark::FieldWriter::add_scalars(&mut ark_prover, &[ark_scalar]).unwrap();
    ark_prover
        .fill_challenge_bytes(&mut ark_challenges)
        .unwrap();

    let mut dalek_chal = [0u8; 16];
    let mut dalek_prover = dalek_io.to_arthur();
    plugins::group::FieldWriter::add_scalars(&mut dalek_prover, &[dalek_scalar]).unwrap();
    dalek_prover.fill_challenge_bytes(&mut dalek_chal).unwrap();

    assert_eq!(ark_challenges, dalek_chal);
}
