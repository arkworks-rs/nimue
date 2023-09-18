use crate::{DefaultHash, Merlin, Safe};

use super::arkworks::prelude::*;
use super::dalek::prelude::*;
use super::zkcrypto::prelude::*;

#[test]
fn compatible_scalars() {
    let ark_scalar = ark_curve25519::Fr::from(0x42);
    // let ark_point = ark_curve25519::EdwardsAffine::generator() * ark_scalar;

    let dalek_scalar = curve25519_dalek::Scalar::from(0x42u8);
    // let dalek_point = curve25519_dalek::constants::ED25519_BASEPOINT_POINT * dalek_scalar;

    let ark_io = IOPattern::<DefaultHash>::new("ark-dalek")
        .absorb_serializable::<ark_curve25519::Fr>(1, "scalar")
        .squeeze(16, "challenge");
    let dalek_io = IOPattern::<DefaultHash>::new("ark-dalek")
        .absorb_scalars(1, "scalar")
        .squeeze(16, "challenge");

    let mut ark_safe = Safe::new(&ark_io);
    let mut ark_chal = [0u8; 16];
    ark_safe.absorb_serializable(&[ark_scalar]).unwrap();
    ark_safe.squeeze(&mut ark_chal).unwrap();
    let mut dalek_safe = Safe::new(&dalek_io);
    let mut dalek_chal = [0u8; 16];
    dalek_safe.absorb_scalars(&[dalek_scalar]).unwrap();
    dalek_safe.squeeze(&mut dalek_chal).unwrap();

    assert_eq!(ark_chal, dalek_chal);
}
