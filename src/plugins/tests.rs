use crate::{DefaultHash, Safe};

use super::arkworks::prelude::*;
use super::dalek::prelude::*;

#[test]
fn compatible_scalars() {
    type G = ark_curve25519::EdwardsProjective;

    let ark_scalar = ark_curve25519::Fr::from(0x42);
    // let ark_point = ark_curve25519::EdwardsAffine::generator() * ark_scalar;

    let dalek_scalar = curve25519_dalek::Scalar::from(0x42u8);
    // let dalek_point = curve25519_dalek::constants::ED25519_BASEPOINT_POINT * dalek_scalar;

    let ark_io =
        ArkGroupIOPattern::<ark_curve25519::EdwardsProjective, DefaultHash>::new("ark-dalek")
            .add_scalars(1, "scalar")
            .challenge_bytes(16, "challenge");
    let dalek_io = IOPattern::<DefaultHash>::new("ark-dalek");
    let dalek_io = DalekIOPattern::add_scalars(dalek_io, 1, "scalar");
    let dalek_io = dalek_io.squeeze(16, "challenge");

    let mut ark_safe = Safe::new(&ark_io);
    let mut ark_chal = [0u8; 16];
    ArkSafe::<G, _>::absorb_scalars(&mut ark_safe, &[ark_scalar]).unwrap();
    ark_safe.squeeze(&mut ark_chal).unwrap();
    let mut dalek_safe = Safe::new(&dalek_io);
    let mut dalek_chal = [0u8; 16];
    dalek_safe.add_scalars(&[dalek_scalar]).unwrap();
    dalek_safe.squeeze_bytes(&mut dalek_chal).unwrap();

    assert_eq!(ark_chal, dalek_chal);
}
