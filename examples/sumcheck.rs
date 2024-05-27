//! This is the example of a.
//!
//! Sumcheck proofs allow to prove that, given a multilinear polynomial $g$
//! defined over field $\mathbb{F}$, the sum of $g$ over
//! $H \subseteq \mathbb{F}$ is equal to $C$.
//!

// TODO Add doc for rust-analyzer.cargo.features for examples.
use ark_ff::PrimeField;
use ark_poly::MultilinearExtension;
use nimue::plugins::ark::{FieldChallenges, FieldIOPattern, FieldWriter};
use nimue::{Arthur, IOPattern, Merlin, ProofResult};

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
    value: &F,
) -> ProofResult<&'a mut Merlin>
where
    F: PrimeField,
    Merlin: FieldWriter<F> + FieldChallenges<F>,
{
    // FIXME
    let num_var = polynomial.num_vars();
    let eval = polynomial.to_evaluations();
    for i in 0..num_var {
        let a = eval.iter().step_by(2).sum();
        let b = eval.iter().skip(1).step_by(2).sum();
        merlin.add_scalars(&[a, b])?;
    }
    Ok(merlin)
}

fn main() {}
