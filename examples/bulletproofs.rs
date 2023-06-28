use ark_bls12_381::G1Projective;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_std::{log2, Zero};
use nimue::arkworks_plugins::{Absorbable, AlgebraicIO};
use nimue::{IOPattern, DefaultHash};
use nimue::{
    arkworks_plugins::{Absorbs, FieldChallenges},
    Duplexer, InvalidTag, Merlin,
};
use rand::rngs::OsRng;

struct Bulletproof<G: AffineRepr> {
    proof: Vec<(G, G)>,
    last: (G::ScalarField, G::ScalarField),
}

trait BulletproofIOPattern {
    fn bulletproof_io<G, S: Duplexer>(&self, len: usize) -> Self
    where
        G: AffineRepr + Absorbable<S::L>;
}

impl BulletproofIOPattern for IOPattern {
    fn bulletproof_io<G, S>(&self, len: usize) -> Self
    where
        G: AffineRepr + Absorbable<S::L>,
        S: Duplexer
    {
        let mut pattern = AlgebraicIO::<S>::from(self).absorb_point::<G>(1);
        for _ in 0..log2(len) {
            pattern = pattern.absorb_point::<G>(2).squeeze_bytes(16);
        }
        pattern.into()
    }
}

fn prove<S, G>(
    transcript: &mut Merlin<S>,
    generators: (&[G], &[G], &G),
    statement: &G,
    witness: (&[G::ScalarField], &[G::ScalarField]),
) -> Result<Bulletproof<G>, InvalidTag>
where
    S: Duplexer,
    G: AffineRepr + Absorbable<S::L>,
{
    assert_eq!(witness.0.len(), witness.1.len());

    if witness.0.len() == 1 {
        assert_eq!(generators.0.len(), 1);

        let g = generators.0[0];
        let h = generators.1[0];
        let u = *generators.2;
        let a = witness.0[0];
        let b = witness.1[0];
        let c = a * b;
        let left = g * a + h * b + u * c;
        let right = *statement;
        println!("{}", (left - right).is_zero());
        return Ok(Bulletproof {
            proof: vec![],
            last: (witness.0[0], witness.1[0]),
        });
    }

    let n = witness.0.len() / 2;
    let (a_left, a_right) = witness.0.split_at(n);
    let (b_left, b_right) = witness.1.split_at(n);
    let (g_left, g_right) = generators.0.split_at(n);
    let (h_left, h_right) = generators.1.split_at(n);
    let u = *generators.2;

    let left = u * inner_prod(a_left, b_right)
        + G::Group::msm(g_right, a_left).unwrap()
        + G::Group::msm(h_left, b_right).unwrap();
    let left_compressed = left.into_affine();

    let right = u * inner_prod(a_right, b_left)
        + G::Group::msm(g_left, a_right).unwrap()
        + G::Group::msm(h_right, b_left).unwrap();
    let right_compressed = right.into_affine();

    transcript.append_element(&left_compressed)?;
    transcript.append_element(&right_compressed)?;
    let x = transcript.short_field_challenge::<G::ScalarField>(16)?;
    let x_inv = x.inverse().expect("You just won the lottery!");

    let new_g = fold_generators(g_left, g_right, &x_inv, &x);
    let new_h = fold_generators(h_left, h_right, &x, &x_inv);
    let new_generators = (&new_g[..], &new_h[..], generators.2);

    let new_a = fold(a_left, a_right, &x, &x_inv);
    let new_b = fold(b_left, b_right, &x_inv, &x);
    let new_witness = (&new_a[..], &new_b[..]);

    let new_statement = (*statement + left * x.square() + right * x_inv.square()).into_affine();

    let mut bulletproof = prove(transcript, new_generators, &new_statement, new_witness)?;
    bulletproof.proof.push((left_compressed, right_compressed));
    Ok(bulletproof)
}

fn verify<G, S>(
    transcript: &mut Merlin<S>,
    generators: (&[G], &[G], &G),
    statement: &G,
    bulletproof: &Bulletproof<G>,
) -> Result<(), InvalidTag>
where
    S: Duplexer,
    G: AffineRepr + Absorbable<S::L>,
{
    let mut g = generators.0.to_vec();
    let mut h = generators.1.to_vec();
    let u = *generators.2;
    let mut statement = *statement;

    let mut n = 1 << bulletproof.proof.len();
    assert_eq!(g.len(), n);
    for (left, right) in bulletproof.proof.iter().rev() {
        n /= 2;

        let (g_left, g_right) = g.split_at(n);
        let (h_left, h_right) = h.split_at(n);

        transcript.append_element(left)?;
        transcript.append_element(right)?;
        let x = transcript.short_field_challenge::<G::ScalarField>(16)?;
        let x_inv = x.inverse().expect("You just won the lottery!");

        g = fold_generators(g_left, g_right, &x_inv, &x);
        h = fold_generators(h_left, h_right, &x, &x_inv);
        statement = (statement + *left * x.square() + *right * x_inv.square()).into_affine();
    }
    let (a, b) = bulletproof.last;
    let c = a * b;
    if (g[0] * a + h[0] * b + u * c - statement).is_zero() {
        Ok(())
    } else {
        Err("Invalid proof".into())
    }
}

fn main() {
    use ark_bls12_381::g1::G1Affine as G;
    use ark_bls12_381::Fr as F;
    use ark_std::UniformRand;

    type H = nimue::DefaultHash;

    let a = [1, 2, 3, 4].iter().map(|&x| F::from(x)).collect::<Vec<_>>();
    let b = [1, 2, 3, 4].iter().map(|&x| F::from(x)).collect::<Vec<_>>();
    let g = (0..a.len())
        .map(|_| G::rand(&mut OsRng))
        .collect::<Vec<_>>();
    let h = (0..a.len())
        .map(|_| G::rand(&mut OsRng))
        .collect::<Vec<_>>();
    let u = G::rand(&mut OsRng);
    let ip = inner_prod(&a, &b);

    let generators = (&g[..], &h[..], &u);
    let statement =
        (G1Projective::msm(&g, &a).unwrap() + G1Projective::msm(&h, &b).unwrap() + u * ip)
            .into_affine();
    let witness = (&a[..], &b[..]);

    let iop = IOPattern::new("example.com").bulletproof_io::<G, H>(a.len());
    let mut transcript = Merlin::new(&iop);
    transcript.append_element(&statement).unwrap();
    let bulletproof =
        prove::<nimue::keccak::Keccak, G>(&mut transcript, generators, &statement, witness)
            .unwrap();
    let mut transcript = Merlin::<nimue::keccak::Keccak>::new(&iop);
    transcript.append_element(&statement).unwrap();
    verify(&mut transcript, generators, &statement, &bulletproof).expect("Invalid proof");
}

fn fold<F: Field>(a: &[F], b: &[F], x: &F, y: &F) -> Vec<F> {
    a.iter()
        .zip(b.iter())
        .map(|(&a, &b)| a * x + b * y)
        .collect()
}

fn fold_generators<G: AffineRepr>(
    a: &[G],
    b: &[G],
    x: &G::ScalarField,
    y: &G::ScalarField,
) -> Vec<G> {
    a.iter()
        .zip(b.iter())
        .map(|(&a, &b)| (a * x + b * y).into_affine())
        .collect()
}

fn inner_prod<F: Field>(a: &[F], b: &[F]) -> F {
    a.iter().zip(b.iter()).map(|(&a, &b)| a * b).sum()
}
