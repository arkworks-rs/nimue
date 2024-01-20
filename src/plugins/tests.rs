use crate::DefaultHash;

use super::arkworks::*;
use super::dalek::*;

#[test]
fn compatible_scalars() {
    let ark_scalar = ark_curve25519::Fr::from(0x42);
    // let ark_point = ark_curve25519::EdwardsAffine::generator() * ark_scalar;

    let dalek_scalar = curve25519_dalek::Scalar::from(0x42u8);
    // let dalek_point = curve25519_dalek::constants::ED25519_BASEPOINT_POINT * dalek_scalar;

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
    ark_prover.challenge_bytes(&mut ark_chal).unwrap();

    let mut dalek_chal = [0u8; 16];
    let mut dalek_prover = dalek_io.to_arthur();
    dalek_prover.add_scalars(&[dalek_scalar]).unwrap();
    dalek_prover.challenge_bytes(&mut dalek_chal).unwrap();

    assert_eq!(ark_chal, dalek_chal);
}
