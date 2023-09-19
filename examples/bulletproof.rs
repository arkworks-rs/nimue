use anyhow::Result;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_std::log2;
use nimue::plugins::arkworks::prelude::*;
use nimue::{Arthur, DuplexHash, IOPattern, InvalidTag};
use rand::rngs::OsRng;

fn fold_generators<A: AffineRepr>(
    a: &[A],
    b: &[A],
    x: &A::ScalarField,
    y: &A::ScalarField,
) -> Vec<A> {
    a.iter()
        .zip(b.iter())
        .map(|(&a, &b)| (a * x + b * y).into_affine())
        .collect()
}

/// Computes the inner prouct of vectors `a` and `b`.
///
/// Useless once https://github.com/arkworks-rs/algebra/pull/665 gets merged.
fn inner_prod<F: Field>(a: &[F], b: &[F]) -> F {
    a.iter().zip(b.iter()).map(|(&a, &b)| a * b).sum()
}

/// Folds together `(a, b)` using challenges `x` and `y`.
fn fold<F: Field>(a: &[F], b: &[F], x: &F, y: &F) -> Vec<F> {
    a.iter()
        .zip(b.iter())
        .map(|(&a, &b)| a * x + b * y)
        .collect()
}

/// The IO Pattern of a bulleproof.
///
/// Defining this as a trait allows us to "attach" the bulletproof IO to
/// the base class [`nimue::IOPattern`] and have other protocol compose the IO pattern.
trait BulletproofIOPattern<G, H, U>
where
    G: CurveGroup,
    U: Unit,
    H: DuplexHash<U>,
{
    fn bulletproof_statement(self) -> Self;
    fn bulletproof_io(self, len: usize) -> Self;
}

impl<H, G> BulletproofIOPattern<G, H, u8> for AlgebraicIOPattern<G, H>
where
    G: CurveGroup,
    H: DuplexHash<u8>,
    IOPattern<H, u8>: ArkIOPattern<G, u8>,
{
    /// The IO of the bulletproof statement (the sole commitment)
    fn bulletproof_statement(self) -> Self {
        self.absorb_points(1, "Ped-commit")
    }

    /// The IO of the bulletproof protocol
    fn bulletproof_io(mut self, len: usize) -> Self {
        for _ in 0..log2(len) {
            self = self
                .absorb_points(2, "round-message")
                .squeeze_scalars(1, "challenge");
        }
        self.absorb_scalars(2, "final-message")
    }
}

fn prove<'a, H, G>(
    arthur: &'a mut Arthur<H>,
    generators: (&[G::Affine], &[G::Affine], &G::Affine),
    statement: &G, // the actual inner-roduct of the witness is not really needed
    witness: (&[G::ScalarField], &[G::ScalarField]),
) -> Result<&'a [u8], anyhow::Error>
where
    H: DuplexHash<u8>,
    G: CurveGroup,
    Arthur<H>: ArkArthur<G, u8>,
{
    assert_eq!(witness.0.len(), witness.1.len());

    if witness.0.len() == 1 {
        assert_eq!(generators.0.len(), 1);

        arthur.absorb_scalars(&[witness.0[0], witness.1[0]])?;
        return Ok(arthur.transcript());
    }

    let n = witness.0.len() / 2;
    let (a_left, a_right) = witness.0.split_at(n);
    let (b_left, b_right) = witness.1.split_at(n);
    let (g_left, g_right) = generators.0.split_at(n);
    let (h_left, h_right) = generators.1.split_at(n);
    let u = *generators.2;

    let left = u * inner_prod(a_left, b_right)
        + G::msm(g_right, a_left).unwrap()
        + G::msm(h_left, b_right).unwrap();

    let right = u * inner_prod(a_right, b_left)
        + G::msm(g_left, a_right).unwrap()
        + G::msm(h_right, b_left).unwrap();

    arthur.absorb_points(&[left, right])?;
    let [x] = arthur.squeeze_scalars()?;
    let x_inv = x.inverse().expect("You just won the lottery!");

    let new_g = fold_generators(g_left, g_right, &x_inv, &x);
    let new_h = fold_generators(h_left, h_right, &x, &x_inv);
    let new_generators = (&new_g[..], &new_h[..], generators.2);

    let new_a = fold(a_left, a_right, &x, &x_inv);
    let new_b = fold(b_left, b_right, &x_inv, &x);
    let new_witness = (&new_a[..], &new_b[..]);

    let new_statement = *statement + left * x.square() + right * x_inv.square();

    let bulletproof = prove(arthur, new_generators, &new_statement, new_witness)?;
    Ok(bulletproof)
}

fn verify<G, H>(
    merlin: &mut Merlin<H>,
    generators: (&[G::Affine], &[G::Affine], &G::Affine),
    statement: &G,
) -> Result<(), InvalidTag>
where
    H: DuplexHash<u8>,
    G: CurveGroup,
    for<'a> Merlin<'a, H, u8>: ArkMerlin<G, u8>,
{
    let mut g = generators.0.to_vec();
    let mut h = generators.1.to_vec();
    let u = generators.2.clone();
    let mut statement = statement.clone();

    let mut n = 1 << ark_std::log2(generators.0.len());
    assert_eq!(g.len(), n);
    while n != 1 {
        let [left, right]: [G; 2] = merlin.absorb_points().unwrap();

        n /= 2;

        let (g_left, g_right) = g.split_at(n);
        let (h_left, h_right) = h.split_at(n);

        let [x]: [G::ScalarField; 1] = merlin.squeeze_scalars().unwrap();
        let x_inv = x.inverse().expect("You just won the lottery!");

        g = fold_generators(g_left, g_right, &x_inv, &x);
        h = fold_generators(h_left, h_right, &x, &x_inv);
        statement = statement + left * x.square() + right * x_inv.square();
    }
    let [a, b]: [G::ScalarField; 2] = merlin.absorb_scalars().unwrap();

    let c = a * b;
    if (g[0] * a + h[0] * b + u * c - statement).is_zero() {
        Ok(())
    } else {
        Err("Invalid proof".into())
    }
}

fn main() {
    use ark_bls12_381::g1::G1Projective as G;
    use ark_ec::Group;
    use ark_std::UniformRand;

    type F = <G as Group>::ScalarField;
    type GAffine = <G as CurveGroup>::Affine;

    // the vector size
    let size = 8u64;

    // initialize the IO Pattern putting the domain separator ("example.com")
    let io_pattern = AlgebraicIOPattern::<G>::new("example.com")
        // add the IO of the bulletproof statement (the commitment)
        .bulletproof_statement()
        // (optional) process the data so far, filling the block till the end.
        .ratchet()
        // add the IO of the bulletproof protocol (the transcript)
        .bulletproof_io(size as usize);

    // the test vectors
    let a = (0..size).map(|x| F::from(x)).collect::<Vec<_>>();
    let b = (0..size).map(|x| F::from(x + 42)).collect::<Vec<_>>();
    let ab = inner_prod(&a, &b);
    // the generators to be used for respectively a, b, ip
    let g = (0..a.len())
        .map(|_| GAffine::rand(&mut OsRng))
        .collect::<Vec<_>>();
    let h = (0..b.len())
        .map(|_| GAffine::rand(&mut OsRng))
        .collect::<Vec<_>>();
    let u = GAffine::rand(&mut OsRng);

    let generators = (&g[..], &h[..], &u);
    let statement = G::msm_unchecked(&g, &a) + G::msm_unchecked(&h, &b) + u * ab;
    let witness = (&a[..], &b[..]);

    let mut arthur = Arthur::new(&io_pattern, OsRng);
    arthur.public_points(&[statement]).unwrap();
    arthur.ratchet().unwrap();
    let proof = prove::<nimue::DefaultHash, G>(&mut arthur, generators, &statement, witness)
        .expect("Error proving");

    let mut verifier_transcript = Merlin::new(&io_pattern, proof);
    verifier_transcript.public_points(&[statement]).unwrap();
    verifier_transcript.ratchet().unwrap();
    verify(&mut verifier_transcript, generators, &statement).expect("Invalid proof");
}
