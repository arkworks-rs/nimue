//! This is the example of a.
//!
//! Sumcheck proofs allow to prove that, given a multilinear polynomial $g$
//! defined over field $\mathbb{F}$, the sum of $g$ over
//! $H \subseteq \mathbb{F}$ is equal to $C$.
//!

// TODO Add doc for rust-analyzer.cargo.features for examples.
use ark_ff::PrimeField;
use ark_poly::MultilinearExtension;
use nimue::plugins::ark::{FieldChallenges, FieldIOPattern, FieldReader, FieldWriter};
use nimue::{Arthur, IOPattern, Merlin, ProofError, ProofResult};

trait SumcheckIOPattern<F: PrimeField> {
    fn add_sumcheck(self, num_var: usize) -> Self;
}

impl<F> SumcheckIOPattern<F> for IOPattern
where
    F: PrimeField,
    IOPattern: FieldIOPattern<F>,
{
    fn add_sumcheck(mut self, num_var: usize) -> Self {
        for _ in 0..num_var {
            self = self
                .add_scalars(1, "partial evaluation")
                .challenge_scalars(1, "sumcheck challenge");
        }
        self = self.add_scalars(1, "folded polynomial");
        self
    }
}

fn prove<'a, F>(
    merlin: &'a mut Merlin,
    polynomial: &impl MultilinearExtension<F>,
) -> ProofResult<&'a mut Merlin>
where
    F: PrimeField,
    Merlin: FieldWriter<F> + FieldChallenges<F>,
{
    let num_var = polynomial.num_vars();
    let mut partial_poly = polynomial.clone();
    for _ in 0..num_var {
        let eval = partial_poly.to_evaluations();
        let a = eval.iter().step_by(2).sum();
        let b = eval.iter().skip(1).step_by(2).sum();
        merlin.add_scalars(&[a, b])?;
        let [r] = merlin.challenge_scalars()?;
        partial_poly = partial_poly.fix_variables(&[r]);
    }
    // The folded polynomial
    let folded = partial_poly.to_evaluations()[0];
    merlin.add_scalars(&[folded])?;
    Ok(merlin)
}

fn verify<F>(
    arthur: &mut Arthur,
    polynomial: &impl MultilinearExtension<F>,
    value: &F,
) -> ProofResult<()>
where
    F: PrimeField,
    for<'a> Arthur<'a>: FieldReader<F> + FieldChallenges<F>,
{
    let mut value = value.clone();
    let num_vars = polynomial.num_vars();
    for _ in 1..num_vars {
        let [a, b] = arthur.next_scalars()?;
        if a + b != value {
            return Err(ProofError::InvalidProof);
        }
        let [r] = arthur.challenge_scalars()?;
        value = a * r + b;
    }
    let [folded] = arthur.next_scalars()?;
    if folded != value {
        Err(ProofError::InvalidProof)
    } else {
        Ok(())
    }
}

fn main() {}
