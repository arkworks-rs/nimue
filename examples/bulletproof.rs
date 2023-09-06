use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_std::log2;
use nimue::plugins::arkworks::prelude::*;
use nimue::{Arthur, DuplexHash, IOPattern, InvalidTag, Merlin};
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

// The bulletproof proof.
struct Bulletproof<G: CurveGroup> {
    /// the prover's messages
    round_msgs: Vec<(G, G)>,
    /// the last round message
    last: (G::ScalarField, G::ScalarField),
}

/// The IO Pattern of a bulleproof.
///
/// Defining this as a trait allows us to "attach" the bulletproof IO to
/// the base class [`nimue::IOPattern`] and have other protocol compose the IO pattern.
trait BulletproofIOPattern {
    fn bulletproof_statement<G, S: DuplexHash>(self) -> Self
    where
        G: CurveGroup;

    fn bulletproof_io<G, S: DuplexHash>(self, len: usize) -> Self
    where
        G: CurveGroup;
}

impl<H: DuplexHash> BulletproofIOPattern for IOPattern<H> {
    /// The IO of the bulletproof statement (the sole commitment)
    fn bulletproof_statement<G, S: DuplexHash>(self) -> Self
    where
        G: CurveGroup,
    {
        self.absorb_serializable::<G>(1, "Pedersen-commitment")
    }

    /// The IO of the bulletproof protocol
    fn bulletproof_io<G, S>(mut self, len: usize) -> Self
    where
        G: CurveGroup,
        S: DuplexHash,
    {
        for _ in 0..log2(len) {
            self = self
                .absorb_serializable::<G>(2, "round-message")
                .squeeze_pfelt::<G::ScalarField>(1, "challenge");
        }
        self
    }
}

fn prove<H, G>(
    transcript: &mut Arthur<H>,
    generators: (&[G::Affine], &[G::Affine], &G::Affine),
    statement: &G::Affine, // the actual inner-roduct of the witness is not really needed
    witness: (&[G::ScalarField], &[G::ScalarField]),
) -> Result<Bulletproof<G>, InvalidTag>
where
    H: DuplexHash<U = u8>,
    G: CurveGroup,
{
    assert_eq!(witness.0.len(), witness.1.len());

    if witness.0.len() == 1 {
        assert_eq!(generators.0.len(), 1);

        return Ok(Bulletproof {
            round_msgs: vec![],
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
        + G::msm(g_right, a_left).unwrap()
        + G::msm(h_left, b_right).unwrap();

    let right = u * inner_prod(a_right, b_left)
        + G::msm(g_left, a_right).unwrap()
        + G::msm(h_right, b_left).unwrap();

    transcript.absorb_serializable(&[left, right]).unwrap();
    let x = transcript.squeeze_pfelt::<G::ScalarField>()?;
    let x_inv = x.inverse().expect("You just won the lottery!");

    let new_g = fold_generators(g_left, g_right, &x_inv, &x);
    let new_h = fold_generators(h_left, h_right, &x, &x_inv);
    let new_generators = (&new_g[..], &new_h[..], generators.2);

    let new_a = fold(a_left, a_right, &x, &x_inv);
    let new_b = fold(b_left, b_right, &x_inv, &x);
    let new_witness = (&new_a[..], &new_b[..]);

    let new_statement = (*statement + left * x.square() + right * x_inv.square()).into_affine();

    let mut bulletproof = prove(transcript, new_generators, &new_statement, new_witness)?;
    // proof will be reverse-order
    bulletproof.round_msgs.push((left, right));
    Ok(bulletproof)
}

fn verify<G, H>(
    transcript: &mut Merlin<H>,
    generators: (&[G::Affine], &[G::Affine], &G::Affine),
    statement: &G::Affine,
    bulletproof: &Bulletproof<G>,
) -> Result<(), InvalidTag>
where
    H: DuplexHash<U = u8>,
    G: CurveGroup,
{
    let mut g = generators.0.to_vec();
    let mut h = generators.1.to_vec();
    let u = *generators.2;
    let mut statement = *statement;

    let mut n = 1 << bulletproof.round_msgs.len();
    assert_eq!(g.len(), n);
    for &(left, right) in bulletproof.round_msgs.iter().rev() {
        n /= 2;

        let (g_left, g_right) = g.split_at(n);
        let (h_left, h_right) = h.split_at(n);

        transcript.absorb_serializable(&[left, right]).unwrap();

        let x = transcript.squeeze_pfelt::<G::ScalarField>()?;
        let x_inv = x.inverse().expect("You just won the lottery!");

        g = fold_generators(g_left, g_right, &x_inv, &x);
        h = fold_generators(h_left, h_right, &x, &x_inv);
        statement = (statement + left * x.square() + right * x_inv.square()).into_affine();
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
    use ark_bls12_381::g1::G1Projective as G;
    use ark_ec::Group;
    use ark_std::UniformRand;

    type F = <G as Group>::ScalarField;
    type GAffine = <G as CurveGroup>::Affine;

    type H = nimue::DefaultHash;
    // the vector size
    let size = 8u64;

    // initialize the IO Pattern putting the domain separator ("example.com")
    let io_pattern = IOPattern::new("example.com")
        // add the IO of the bulletproof statement (the commitment)
        .bulletproof_statement::<G, H>()
        // (optional) process the data so far, filling the block till the end.
        .ratchet()
        // add the IO of the bulletproof protocol (the transcript)
        .bulletproof_io::<G, H>(size as usize);

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
    let statement = (G::msm_unchecked(&g, &a) + G::msm_unchecked(&h, &b) + u * ab).into_affine();
    let witness = (&a[..], &b[..]);

    let mut prover_transcript = Arthur::new(&io_pattern, OsRng);
    prover_transcript.absorb_serializable(&[statement]).unwrap();
    prover_transcript.ratchet().unwrap();
    let bulletproof =
        prove::<nimue::DefaultHash, G>(&mut prover_transcript, generators, &statement, witness)
            .expect("Error proving");

    let mut verifier_transcript = Merlin::<nimue::DefaultHash>::new(&io_pattern);
    verifier_transcript
        .absorb_serializable(&[statement])
        .unwrap();
    verifier_transcript.ratchet().unwrap();
    verify(
        &mut verifier_transcript,
        generators,
        &statement,
        &bulletproof,
    )
    .expect("Invalid proof");
}
