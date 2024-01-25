use crate::DefaultHash;

use super::arkworks::*;
use super::dalek::*;

/// Compatibility betweek arkworks and dalek can only be tested when handling scalars.
/// In fact, arkworks does not yet implement ristretto points as per `curve25519_dalek::ristretto::Ristretto`
#[test]
fn test_compatible_ark_dalek() {
    let ark_scalar = ark_curve25519::Fr::from(0x42);
    let dalek_scalar = curve25519_dalek::Scalar::from(0x42u64);

    // let ark_point = ark_curve25519::EdwardsProjective::generator() * ark_scalar;
    // let dalek_point = curve25519_dalek::constants::ED25519_BASEPOINT_POINT * dalek_scalar;

    let ark_io =
        ArkGroupIOPattern::<ark_curve25519::EdwardsProjective, DefaultHash>::new("ark-dalek")
            .add_scalars(1, "scalar")
            .challenge_bytes(16, "challenge");
    // .add_points(1, "point")
    // .challenge_bytes(16, "challenge");
    let dalek_io = DalekIOPattern::<DefaultHash>::new("ark-dalek")
        .add_scalars(1, "scalar")
        .challenge_bytes(16, "challenge");
    // .add_points(1, "point")
    // .challenge_bytes(16, "challenge");

    let mut ark_challenges = [0u8; 16];
    let mut ark_prover = ark_io.to_arthur();
    ark_prover.add_scalars(&[ark_scalar]).unwrap();
    ark_prover
        .fill_challenge_bytes(&mut ark_challenges)
        .unwrap();
    // ark_prover.add_points(&[ark_point]);

    let mut dalek_chal = [0u8; 16];
    let mut dalek_prover = dalek_io.to_arthur();
    dalek_prover.add_scalars(&[dalek_scalar]).unwrap();
    dalek_prover.fill_challenge_bytes(&mut dalek_chal).unwrap();
    // dalek_prover.add_points(&[dalek_point]).unwrap();
    // dalek_prover.challenge_bytes(output)

    assert_eq!(ark_challenges, dalek_chal);
}

#[test]
fn test_compatible_points() {
    let ark_scalar = ark_curve25519::Fr::from(0x42);

    let dalek_scalar = curve25519_dalek::Scalar::from(0x42u8);

    let ark_io =
        ArkGroupIOPattern::<ark_curve25519::EdwardsProjective, DefaultHash>::new("ark-dalek")
            .add_scalars(1, "scalar")
            .challenge_bytes(16, "challenge");
    let dalek_io = DalekIOPattern::<DefaultHash>::new("ark-dalek")
        .add_scalars(1, "scalar")
        .challenge_bytes(16, "challenge");

    let mut ark_chal = [0u8; 16];
    let mut ark_prover = ark_io.to_arthur();
    ark_prover.add_scalars(&[ark_scalar]).unwrap();
    ark_prover.fill_challenge_bytes(&mut ark_chal).unwrap();

    let mut dalek_chal = [0u8; 16];
    let mut dalek_prover = dalek_io.to_arthur();
    dalek_prover.add_scalars(&[dalek_scalar]).unwrap();
    dalek_prover.fill_challenge_bytes(&mut dalek_chal).unwrap();

    assert_eq!(ark_chal, dalek_chal);
}
