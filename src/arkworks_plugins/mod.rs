mod absorbs;
mod field_challenges;
mod iopattern;

pub use absorbs::Absorbs;

use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    AffineRepr,
};
use ark_ff::{BigInteger, Fp, FpConfig, PrimeField};
use ark_serialize::CanonicalSerialize;
pub use field_challenges::FieldChallenges;
pub use iopattern::AlgebraicIO;

use crate::Lane;

/// Provides a way to absorb generically arkworks types into a sponge.
///
/// This function is similar to the trait [`Absorb`](https://github.com/arkworks-rs/crypto-primitives/blob/main/src/sponge/absorb.rs) from arkworks, with slight changes to satisfy the stricter absorption model of the SAFE API.
pub trait Absorbable<Other>: Sized {
    fn absorb_size() -> usize;
    fn to_absorbable(myself: &Self) -> Vec<Other>;
}

impl<const N: usize, P: FpConfig<N>> Absorbable<Fp<P, N>> for Fp<P, N> {
    fn absorb_size() -> usize {
        1
    }

    fn to_absorbable(myself: &Self) -> Vec<Self> {
        vec![*myself]
    }
}

impl<const N: usize, P: FpConfig<N>> Absorbable<u8> for Fp<P, N> {
    fn absorb_size() -> usize {
        Self::default().compressed_size()
    }

    fn to_absorbable(myself: &Self) -> Vec<u8> {
        myself.into_bigint().to_bytes_le()
    }
}

impl<const N: usize, C: FpConfig<N>, P: SWCurveConfig<BaseField = Fp<C, N>>> Absorbable<Fp<C, N>>
    for Affine<P>
{
    fn absorb_size() -> usize {
        1
    }

    fn to_absorbable(myself: &Self) -> Vec<Fp<C, N>> {
        let (&x, &y) = myself.xy().unwrap();
        vec![x, y]
    }
}

impl<P: SWCurveConfig, L: Lane> Absorbable<L> for Affine<P> {
    fn absorb_size() -> usize {
        usize::div_ceil(Self::default().compressed_size(), L::compressed_size())
    }

    fn to_absorbable(myself: &Self) -> Vec<L> {
        let mut output = Vec::new();
        myself.serialize_compressed(&mut output).unwrap();
        L::from_bytes(&output)
    }
}

impl<L: Lane, A: Absorbable<L>, const N: usize> Absorbable<L> for &[A; N] {
    fn absorb_size() -> usize {
        A::absorb_size() * N
    }

    fn to_absorbable(myself: &Self) -> Vec<L> {
        myself.iter().flat_map(|x| A::to_absorbable(x)).collect()
    }
}

#[macro_export]
macro_rules! impl_absorbable {
    ($t:ty) => {
        impl Absorbable for $t {
            fn absorb_size() -> usize {
                usize::div_ceil(core::mem::size_of::<$t>(), Other::packed_size())
            }

            fn to_absorbable(myself: &Self) -> Vec<Other> {
                Other::pack_bytes(&myself)
            }
        }
    };
}

/// Implements a [`Lane`] on the fly for a [`ark_ff::PrimeField`] type.
///
/// Takes as input the type, and the number of bytes that can be extracted from an integer mod p. Refer to `scripts/useful_bits_modp.py` for a way to compute this number.
/// XXX. For now unused until this feature stabilizes.
#[allow(unused)]
macro_rules! impl_lane {
    ($t:ty, $n: expr) => {
        impl Lane for $t {
            fn random_bytes_size() -> usize {
                $n
            }

            fn packed_size() -> usize {
                use ark_ff::PrimeField;

                (Self::MODULUS_BIT_SIZE as usize - 1) / 8
            }

            fn to_random_bytes(a: &[Self], dst: &mut [u8]) {
                use ark_ff::{BigInteger, PrimeField};

                let length = usize::min(Self::random_bytes_size(), dst.len());
                let bytes = a[0].into_bigint().to_bytes_le();
                dst[..length].copy_from_slice(&bytes[..length]);

                if dst.len() > length {
                    Self::fill_bytes(&a[1..], &mut dst[length..]);
                }
            }

            fn to_bytes(a: &[Self], dst: &mut [u8]) {
                use ark_ff::{BigInteger, PrimeField};

                if a.is_empty() {
                    return;
                } else {
                    let bytes = a[0].into_bigint().to_bytes_le();
                    dst[..bytes.len()].copy_from_slice(&bytes);
                    Self::to_bytes(&a[1..], &mut dst[bytes.len()..]);
                }
            }

            fn pack_bytes(bytes: &[u8]) -> Vec<Self> {
                use ark_ff::Field;

                let mut packed = Vec::new();
                for chunk in bytes.chunks(Self::packed_size()) {
                    packed.push(Self::from_random_bytes(chunk).unwrap());
                }
                packed
            }
        }
    };
}
